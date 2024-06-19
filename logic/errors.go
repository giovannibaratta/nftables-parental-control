package logic

type InvalidMacAddressError struct {
	Err error
}

func (e *InvalidMacAddressError) Error() string {
	return e.Err.Error()
}
