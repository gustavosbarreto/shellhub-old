package main

import (
	"C"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	sshserver "github.com/gliderlabs/ssh"
	"github.com/kr/pty"
	"github.com/sirupsen/logrus"
)

/*
#cgo LDFLAGS: -lcrypt
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <crypt.h>
#include <shadow.h>
#include <string.h>
#include <pwd.h>
*/
import "C"
import (
	"bufio"
	"log"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func Auth(user string, passwd string) bool {
	cuser := C.CString(user)
	defer C.free(unsafe.Pointer(cuser))

	cpasswd := C.CString(passwd)
	defer C.free(unsafe.Pointer(cpasswd))

	cfilename := C.CString("/host/etc/shadow")
	defer C.free(unsafe.Pointer(cfilename))

	cmode := C.CString("r")
	defer C.free(unsafe.Pointer(cmode))

	f := C.fopen(cfilename, cmode)
	defer C.fclose(f)

	var pwd *C.struct_spwd
	for {
		if pwd = C.fgetspent(f); pwd == nil {
			return false
		}

		if C.strcmp(cuser, pwd.sp_namp) == 0 {
			break
		}
	}

	if pwd == nil {
		return false
	}

	crypted := C.crypt(cpasswd, pwd.sp_pwdp)

	if C.strcmp(crypted, pwd.sp_pwdp) != 0 {
		return false
	}

	return true
}

func lookupUser(username string) *user.User {
	file, err := os.Open("/host/etc/passwd")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")

		user := &user.User{
			Uid:      parts[2],
			Gid:      parts[3],
			Username: parts[0],
			Name:     parts[4],
			HomeDir:  parts[5],
		}

		if user.Username == username {
			return user
		}
	}

	return nil
}

type SSHServer struct {
	sshd *sshserver.Server
}

func NewSSHServer(port int) *SSHServer {
	s := &SSHServer{}

	s.sshd = &sshserver.Server{
		Addr: fmt.Sprintf("localhost:%d", port),
		PasswordHandler: func(ctx sshserver.Context, pass string) bool {
			if Auth(ctx.User(), pass) == true {
				return true
			}

			return false
		},
		PublicKeyHandler: s.publicKeyHandler,
		Handler:          s.sessionHandler,
	}

	return s
}

func (s *SSHServer) ListenAndServe() error {
	return s.sshd.ListenAndServe()
}

func (s *SSHServer) sessionHandler(session sshserver.Session) {
	sspty, winCh, isPty := session.Pty()

	if isPty {
		scmd := newShellCmd(session.User(), sspty.Term)

		spty, err := pty.Start(scmd)
		if err != nil {
			logrus.Warn(err)
		}

		go func() {
			for win := range winCh {
				setWinsize(spty, win.Width, win.Height)
			}
		}()

		go func() {
			_, err := io.Copy(session, spty)
			if err != nil {
				logrus.Warn(err)
			}
		}()

		go func() {
			_, err := io.Copy(spty, session)
			if err != nil {
				logrus.Warn(err)
			}
		}()

		err = scmd.Wait()
		if err != nil {
			logrus.Warn(err)
		}
	} else {
		u := lookupUser(session.User())

		cmd := exec.Command(session.Command()[0], session.Command()[1:]...)
		cmd.Dir = u.HomeDir
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Chroot = "/host"

		stdout, _ := cmd.StdoutPipe()
		stdin, _ := cmd.StdinPipe()

		cmd.Start()

		go func() {
			if _, err := io.Copy(stdin, session); err != nil {
				fmt.Println(err)
			}
		}()

		go func() {
			if _, err := io.Copy(session, stdout); err != nil {
				fmt.Println(err)
			}
		}()

		cmd.Wait()
	}
}

func (s *SSHServer) publicKeyHandler(ctx sshserver.Context, key sshserver.PublicKey) bool {
	return true
}

func newShellCmd(username string, term string) *exec.Cmd {
	shell := os.Getenv("SHELL")

	if shell == "" {
		shell = "/bin/sh"
	}

	if term == "" {
		term = "xterm"
	}

	u := lookupUser(username)
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	cmd := exec.Command(shell, "-"+filepath.Base(shell))
	cmd.Env = []string{
		"TERM=" + term,
		"HOME=" + u.HomeDir,
		"SHELL=" + shell,
	}
	cmd.Dir = u.HomeDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Chroot = "/host"
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}

	return cmd
}

func setWinsize(f *os.File, w, h int) {
	size := &struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0}
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(size)))
}
