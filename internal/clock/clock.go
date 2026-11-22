// Package clock 提供可控时钟，让缓存 TTL、故障宽限等时间相关逻辑可确定性测试。
package clock

import "time"

// Clock 抽象校验器依赖的时间源。
type Clock interface {
	Now() time.Time
}

// Real 使用系统墙上时间。
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fake 是手动推进的测试时钟，永远不会自己走动。
type Fake struct {
	t time.Time
}

func NewFake(start time.Time) *Fake { return &Fake{t: start} }

func (f *Fake) Now() time.Time { return f.t }

// Advance 将时钟向前移动 d。
func (f *Fake) Advance(d time.Duration) { f.t = f.t.Add(d) }
