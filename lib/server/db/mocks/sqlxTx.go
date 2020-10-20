// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	sql "database/sql"
	sync "sync"

	db "github.com/tw-bc-group/fabric-ca-gm/lib/server/db"
	sqlx "github.com/jmoiron/sqlx"
)

type SqlxTx struct {
	CommitStub        func() error
	commitMutex       sync.RWMutex
	commitArgsForCall []struct {
	}
	commitReturns struct {
		result1 error
	}
	commitReturnsOnCall map[int]struct {
		result1 error
	}
	ExecStub        func(string, ...interface{}) (sql.Result, error)
	execMutex       sync.RWMutex
	execArgsForCall []struct {
		arg1 string
		arg2 []interface{}
	}
	execReturns struct {
		result1 sql.Result
		result2 error
	}
	execReturnsOnCall map[int]struct {
		result1 sql.Result
		result2 error
	}
	GetStub        func(interface{}, string, ...interface{}) error
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		arg1 interface{}
		arg2 string
		arg3 []interface{}
	}
	getReturns struct {
		result1 error
	}
	getReturnsOnCall map[int]struct {
		result1 error
	}
	QueryxStub        func(string, ...interface{}) (*sqlx.Rows, error)
	queryxMutex       sync.RWMutex
	queryxArgsForCall []struct {
		arg1 string
		arg2 []interface{}
	}
	queryxReturns struct {
		result1 *sqlx.Rows
		result2 error
	}
	queryxReturnsOnCall map[int]struct {
		result1 *sqlx.Rows
		result2 error
	}
	RebindStub        func(string) string
	rebindMutex       sync.RWMutex
	rebindArgsForCall []struct {
		arg1 string
	}
	rebindReturns struct {
		result1 string
	}
	rebindReturnsOnCall map[int]struct {
		result1 string
	}
	RollbackStub        func() error
	rollbackMutex       sync.RWMutex
	rollbackArgsForCall []struct {
	}
	rollbackReturns struct {
		result1 error
	}
	rollbackReturnsOnCall map[int]struct {
		result1 error
	}
	SelectStub        func(interface{}, string, ...interface{}) error
	selectMutex       sync.RWMutex
	selectArgsForCall []struct {
		arg1 interface{}
		arg2 string
		arg3 []interface{}
	}
	selectReturns struct {
		result1 error
	}
	selectReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *SqlxTx) Commit() error {
	fake.commitMutex.Lock()
	ret, specificReturn := fake.commitReturnsOnCall[len(fake.commitArgsForCall)]
	fake.commitArgsForCall = append(fake.commitArgsForCall, struct {
	}{})
	fake.recordInvocation("Commit", []interface{}{})
	fake.commitMutex.Unlock()
	if fake.CommitStub != nil {
		return fake.CommitStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.commitReturns
	return fakeReturns.result1
}

func (fake *SqlxTx) CommitCallCount() int {
	fake.commitMutex.RLock()
	defer fake.commitMutex.RUnlock()
	return len(fake.commitArgsForCall)
}

func (fake *SqlxTx) CommitCalls(stub func() error) {
	fake.commitMutex.Lock()
	defer fake.commitMutex.Unlock()
	fake.CommitStub = stub
}

func (fake *SqlxTx) CommitReturns(result1 error) {
	fake.commitMutex.Lock()
	defer fake.commitMutex.Unlock()
	fake.CommitStub = nil
	fake.commitReturns = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) CommitReturnsOnCall(i int, result1 error) {
	fake.commitMutex.Lock()
	defer fake.commitMutex.Unlock()
	fake.CommitStub = nil
	if fake.commitReturnsOnCall == nil {
		fake.commitReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.commitReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) Exec(arg1 string, arg2 ...interface{}) (sql.Result, error) {
	fake.execMutex.Lock()
	ret, specificReturn := fake.execReturnsOnCall[len(fake.execArgsForCall)]
	fake.execArgsForCall = append(fake.execArgsForCall, struct {
		arg1 string
		arg2 []interface{}
	}{arg1, arg2})
	fake.recordInvocation("Exec", []interface{}{arg1, arg2})
	fake.execMutex.Unlock()
	if fake.ExecStub != nil {
		return fake.ExecStub(arg1, arg2...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.execReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *SqlxTx) ExecCallCount() int {
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	return len(fake.execArgsForCall)
}

func (fake *SqlxTx) ExecCalls(stub func(string, ...interface{}) (sql.Result, error)) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = stub
}

func (fake *SqlxTx) ExecArgsForCall(i int) (string, []interface{}) {
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	argsForCall := fake.execArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *SqlxTx) ExecReturns(result1 sql.Result, result2 error) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = nil
	fake.execReturns = struct {
		result1 sql.Result
		result2 error
	}{result1, result2}
}

func (fake *SqlxTx) ExecReturnsOnCall(i int, result1 sql.Result, result2 error) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = nil
	if fake.execReturnsOnCall == nil {
		fake.execReturnsOnCall = make(map[int]struct {
			result1 sql.Result
			result2 error
		})
	}
	fake.execReturnsOnCall[i] = struct {
		result1 sql.Result
		result2 error
	}{result1, result2}
}

func (fake *SqlxTx) Get(arg1 interface{}, arg2 string, arg3 ...interface{}) error {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		arg1 interface{}
		arg2 string
		arg3 []interface{}
	}{arg1, arg2, arg3})
	fake.recordInvocation("Get", []interface{}{arg1, arg2, arg3})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getReturns
	return fakeReturns.result1
}

func (fake *SqlxTx) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *SqlxTx) GetCalls(stub func(interface{}, string, ...interface{}) error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = stub
}

func (fake *SqlxTx) GetArgsForCall(i int) (interface{}, string, []interface{}) {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	argsForCall := fake.getArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *SqlxTx) GetReturns(result1 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) GetReturnsOnCall(i int, result1 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) Queryx(arg1 string, arg2 ...interface{}) (*sqlx.Rows, error) {
	fake.queryxMutex.Lock()
	ret, specificReturn := fake.queryxReturnsOnCall[len(fake.queryxArgsForCall)]
	fake.queryxArgsForCall = append(fake.queryxArgsForCall, struct {
		arg1 string
		arg2 []interface{}
	}{arg1, arg2})
	fake.recordInvocation("Queryx", []interface{}{arg1, arg2})
	fake.queryxMutex.Unlock()
	if fake.QueryxStub != nil {
		return fake.QueryxStub(arg1, arg2...)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.queryxReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *SqlxTx) QueryxCallCount() int {
	fake.queryxMutex.RLock()
	defer fake.queryxMutex.RUnlock()
	return len(fake.queryxArgsForCall)
}

func (fake *SqlxTx) QueryxCalls(stub func(string, ...interface{}) (*sqlx.Rows, error)) {
	fake.queryxMutex.Lock()
	defer fake.queryxMutex.Unlock()
	fake.QueryxStub = stub
}

func (fake *SqlxTx) QueryxArgsForCall(i int) (string, []interface{}) {
	fake.queryxMutex.RLock()
	defer fake.queryxMutex.RUnlock()
	argsForCall := fake.queryxArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *SqlxTx) QueryxReturns(result1 *sqlx.Rows, result2 error) {
	fake.queryxMutex.Lock()
	defer fake.queryxMutex.Unlock()
	fake.QueryxStub = nil
	fake.queryxReturns = struct {
		result1 *sqlx.Rows
		result2 error
	}{result1, result2}
}

func (fake *SqlxTx) QueryxReturnsOnCall(i int, result1 *sqlx.Rows, result2 error) {
	fake.queryxMutex.Lock()
	defer fake.queryxMutex.Unlock()
	fake.QueryxStub = nil
	if fake.queryxReturnsOnCall == nil {
		fake.queryxReturnsOnCall = make(map[int]struct {
			result1 *sqlx.Rows
			result2 error
		})
	}
	fake.queryxReturnsOnCall[i] = struct {
		result1 *sqlx.Rows
		result2 error
	}{result1, result2}
}

func (fake *SqlxTx) Rebind(arg1 string) string {
	fake.rebindMutex.Lock()
	ret, specificReturn := fake.rebindReturnsOnCall[len(fake.rebindArgsForCall)]
	fake.rebindArgsForCall = append(fake.rebindArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Rebind", []interface{}{arg1})
	fake.rebindMutex.Unlock()
	if fake.RebindStub != nil {
		return fake.RebindStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.rebindReturns
	return fakeReturns.result1
}

func (fake *SqlxTx) RebindCallCount() int {
	fake.rebindMutex.RLock()
	defer fake.rebindMutex.RUnlock()
	return len(fake.rebindArgsForCall)
}

func (fake *SqlxTx) RebindCalls(stub func(string) string) {
	fake.rebindMutex.Lock()
	defer fake.rebindMutex.Unlock()
	fake.RebindStub = stub
}

func (fake *SqlxTx) RebindArgsForCall(i int) string {
	fake.rebindMutex.RLock()
	defer fake.rebindMutex.RUnlock()
	argsForCall := fake.rebindArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SqlxTx) RebindReturns(result1 string) {
	fake.rebindMutex.Lock()
	defer fake.rebindMutex.Unlock()
	fake.RebindStub = nil
	fake.rebindReturns = struct {
		result1 string
	}{result1}
}

func (fake *SqlxTx) RebindReturnsOnCall(i int, result1 string) {
	fake.rebindMutex.Lock()
	defer fake.rebindMutex.Unlock()
	fake.RebindStub = nil
	if fake.rebindReturnsOnCall == nil {
		fake.rebindReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.rebindReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *SqlxTx) Rollback() error {
	fake.rollbackMutex.Lock()
	ret, specificReturn := fake.rollbackReturnsOnCall[len(fake.rollbackArgsForCall)]
	fake.rollbackArgsForCall = append(fake.rollbackArgsForCall, struct {
	}{})
	fake.recordInvocation("Rollback", []interface{}{})
	fake.rollbackMutex.Unlock()
	if fake.RollbackStub != nil {
		return fake.RollbackStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.rollbackReturns
	return fakeReturns.result1
}

func (fake *SqlxTx) RollbackCallCount() int {
	fake.rollbackMutex.RLock()
	defer fake.rollbackMutex.RUnlock()
	return len(fake.rollbackArgsForCall)
}

func (fake *SqlxTx) RollbackCalls(stub func() error) {
	fake.rollbackMutex.Lock()
	defer fake.rollbackMutex.Unlock()
	fake.RollbackStub = stub
}

func (fake *SqlxTx) RollbackReturns(result1 error) {
	fake.rollbackMutex.Lock()
	defer fake.rollbackMutex.Unlock()
	fake.RollbackStub = nil
	fake.rollbackReturns = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) RollbackReturnsOnCall(i int, result1 error) {
	fake.rollbackMutex.Lock()
	defer fake.rollbackMutex.Unlock()
	fake.RollbackStub = nil
	if fake.rollbackReturnsOnCall == nil {
		fake.rollbackReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.rollbackReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) Select(arg1 interface{}, arg2 string, arg3 ...interface{}) error {
	fake.selectMutex.Lock()
	ret, specificReturn := fake.selectReturnsOnCall[len(fake.selectArgsForCall)]
	fake.selectArgsForCall = append(fake.selectArgsForCall, struct {
		arg1 interface{}
		arg2 string
		arg3 []interface{}
	}{arg1, arg2, arg3})
	fake.recordInvocation("Select", []interface{}{arg1, arg2, arg3})
	fake.selectMutex.Unlock()
	if fake.SelectStub != nil {
		return fake.SelectStub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.selectReturns
	return fakeReturns.result1
}

func (fake *SqlxTx) SelectCallCount() int {
	fake.selectMutex.RLock()
	defer fake.selectMutex.RUnlock()
	return len(fake.selectArgsForCall)
}

func (fake *SqlxTx) SelectCalls(stub func(interface{}, string, ...interface{}) error) {
	fake.selectMutex.Lock()
	defer fake.selectMutex.Unlock()
	fake.SelectStub = stub
}

func (fake *SqlxTx) SelectArgsForCall(i int) (interface{}, string, []interface{}) {
	fake.selectMutex.RLock()
	defer fake.selectMutex.RUnlock()
	argsForCall := fake.selectArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *SqlxTx) SelectReturns(result1 error) {
	fake.selectMutex.Lock()
	defer fake.selectMutex.Unlock()
	fake.SelectStub = nil
	fake.selectReturns = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) SelectReturnsOnCall(i int, result1 error) {
	fake.selectMutex.Lock()
	defer fake.selectMutex.Unlock()
	fake.SelectStub = nil
	if fake.selectReturnsOnCall == nil {
		fake.selectReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.selectReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *SqlxTx) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.commitMutex.RLock()
	defer fake.commitMutex.RUnlock()
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.queryxMutex.RLock()
	defer fake.queryxMutex.RUnlock()
	fake.rebindMutex.RLock()
	defer fake.rebindMutex.RUnlock()
	fake.rollbackMutex.RLock()
	defer fake.rollbackMutex.RUnlock()
	fake.selectMutex.RLock()
	defer fake.selectMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *SqlxTx) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ db.SqlxTx = new(SqlxTx)
