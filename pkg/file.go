package pkg

import (
	"fmt"
	"os"
)

// readbpf.c file
func ReadbpfCode(chrootProgramPath string) ([]byte, error) {

	// Open source file
	file, err := os.Open(chrootProgramPath)
	if err != nil {
		return nil, fmt.Errorf("error opening source file:%v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("error getting file information:%v", err)
	}

	srcCode := make([]byte, fileInfo.Size())
	_, err = file.Read(srcCode)
	if err != nil {
		return nil, fmt.Errorf("error reading source file:%v", err)
	}

	return srcCode, nil
}
