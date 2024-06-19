package nftables

type NftError struct {
	Err error
}

func (e *NftError) Error() string {
	return e.Err.Error()
}
