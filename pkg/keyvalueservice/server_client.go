// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyvalueservice

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
)

type ListenFunc func() (net.Listener, error)
type ConnectFunc func() (net.Conn, error)

type KvServer struct {
	listenFunc ListenFunc
	manager    *KvManager
	watcher    *KvWatcher
	log        *logrus.Entry
	errDelay   time.Duration
}

func NewKvServer(lf ListenFunc, m *KvManager, w *KvWatcher,
	l *logrus.Logger) *KvServer {
	return &KvServer{
		listenFunc: lf,
		manager:    m,
		watcher:    w,
		log:        l.WithField("ctx", "KvServer"),
		errDelay:   time.Duration(10 * time.Second)}
}

func (s *KvServer) Watcher() *KvWatcher {
	return s.watcher
}

func (s *KvServer) Run(stopCh <-chan struct{}) {
	accepted := sync.Map{}
	cancelled := false
	var savedListener atomic.Value
	go func() {
		<-stopCh
		cancelled = true
		l := savedListener.Load()
		if l != nil {
			l.(net.Listener).Close()
		}
	}()
	for !cancelled && s.listenFunc != nil {
		s.log.Debug("Trying to listen for connections")
		listener, err := s.listenFunc()
		if err != nil {
			s.log.Error("Unable to listen for connections: ", err)
		} else {
			savedListener.Store(listener)
			for !cancelled {
				s.log.Debug("Waiting to accept")
				conn, err := listener.Accept()
				if err != nil {
					s.log.Error("Failed to accept connection: ", err)
					break
				}
				if conn == nil {
					continue
				}
				connLog := s.log.WithField("remote",
					conn.RemoteAddr().String())
				connLog.Debug("Accepted new connection")

				rpcServer, rpcService, err := NewKvRpcServer(s.manager)
				if err != nil {
					connLog.Error("Unable to create RPC server: ", err)
					conn.Close()
					cancelled = true // no point continuing to listen
					continue
				}

				cdc := NewMultiplexCodec(
					&closer{Conn: conn, svc: rpcService, log: connLog})
				accepted.Store(cdc, struct{}{})
				go func() {
					if s.watcher != nil {
						connLog.Debug("Watching connection")
						s.watcher.ServeConn(cdc)
					}
					connLog.Debug("Serving connection")
					rpcServer.ServeCodec(cdc)
					connLog.Debug("Finished serving connection")
					cdc.Close()
					accepted.Delete(cdc)
				}()
			}
			listener.Close()
		}
		if !cancelled && err != nil {
			// TOOD Use interruptible delay
			time.Sleep(s.errDelay)
		}
	}
	accepted.Range(func(key, value interface{}) bool {
		cdc := key.(*MultiplexCodec)
		cdc.Close()
		return true
	})
}

type KvClient struct {
	connectFunc ConnectFunc
	manager     *KvManager
	watcher     *KvWatcher
	log         *logrus.Entry
	errDelay    time.Duration
}

func NewKvClient(cf ConnectFunc, m *KvManager, w *KvWatcher,
	l *logrus.Logger) *KvClient {
	return &KvClient{
		connectFunc: cf,
		manager:     m,
		watcher:     w,
		log:         l.WithField("ctx", "KvClient"),
		errDelay:    time.Duration(10 * time.Second)}
}

func (c *KvClient) Watcher() *KvWatcher {
	return c.watcher
}

func (c *KvClient) Run(stopCh <-chan struct{}) {
	cancelled := false
	var savedConn atomic.Value
	go func() {
		<-stopCh
		cancelled = true
		c := savedConn.Load()
		if c != nil {
			c.(*MultiplexCodec).Close()
		}
	}()
	iter := 0
	for !cancelled && c.connectFunc != nil {
		iterLog := c.log.WithField("iter", iter)
		iter++
		iterLog.Debug("Connecting to server")
		conn, err := c.connectFunc()
		if err != nil {
			iterLog.Error("Failed to connect to server: ", err)
			// TOOD Use interruptible delay
			time.Sleep(c.errDelay)
		} else {
			connLog := iterLog.WithField("remote", conn.RemoteAddr().String())
			connLog.Debug("Connection successful")

			rpcServer, rpcService, err := NewKvRpcServer(c.manager)
			if err != nil {
				connLog.Error("Unable to create RPC server: ", err)
				conn.Close()
				return
			}

			cdc := NewMultiplexCodec(
				&closer{Conn: conn, svc: rpcService, log: connLog})
			savedConn.Store(cdc)
			if c.watcher != nil {
				connLog.Debug("Watching connection")
				c.watcher.ServeConn(cdc)
			}
			connLog.Debug("Serving connection")
			rpcServer.ServeCodec(cdc)
			connLog.Debug("Finished serving connection")
			cdc.Close()
		}
	}
}

type closer struct {
	net.Conn
	svc *KvService
	log *logrus.Entry
}

func (c *closer) Close() error {
	err := c.Conn.Close()
	if err == nil && c.svc != nil {
		c.log.Info("Aborting watches on close")
		c.svc.abortWatch()
	}
	return err
}
