package pjlink

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

const pjLinkPort = "4352"

type PJProjector struct {
	Address  string
	Port     string
	Password string
}

func NewProjector(IP string, password string) *PJProjector {
	return &PJProjector{
		Address:  IP,
		Port:     pjLinkPort,
		Password: password,
	}
}

//--------------------------------------------------------------------------------------------------------------------//
//--------------- Functional Calls -----------------------------------------------------------------------------------//
//--------------------------------------------------------------------------------------------------------------------//

//--------------- Power ----------------------------------------------------------------------------------------------//

func (pr *PJProjector) GetPowerStatus() (*PJResponse, error) {
	req := PJRequest{
		Class:     1,
		Command:   "POWR",
		Parameter: "?",
	}

	return pr.SendRequest(req)
}

func (pr *PJProjector) TurnOn() error {
	req := PJRequest{
		Class:     1,
		Command:   "POWR",
		Parameter: "1",
	}

	resp, err := pr.SendRequest(req)
	if err != nil {
		return err
	}

	if resp.Success() {
		return nil
	}

	return errors.New("Could not turn on Projector")
}

func (pr *PJProjector) TurnOff() error {
	req := PJRequest{
		Class:     1,
		Command:   "POWR",
		Parameter: "0",
	}

	resp, err := pr.SendRequest(req)
	if err != nil {
		return err
	}

	if resp.Success() {
		return nil
	}

	return errors.New("Could not turn off Projector")
}

func (pr *PJProjector) GetProperty(property string) (string, error) {
	var request PJRequest

	request.Class = 1
	request.Command = property
	request.Parameter = "?"

	resp, err := pr.SendRequest(request)

	if err != nil {
		return "", err
	}

	if len(resp.Response) == 0 {
		return "", errors.New("empty PJLink response")
	}

	return resp.Response[0], nil
}

func (pr *PJProjector) GetPropertyArray(property string) ([]string, error) {
	var request PJRequest

	request.Class = 1
	request.Command = property
	request.Parameter = "?"

	resp, err := pr.SendRequest(request)

	if err != nil {
		return make([]string, 0), err
	}

	return resp.Response, nil
}

func (pr *PJProjector) SetProperty(property string, val string) error {
	var request PJRequest

	request.Class = 1
	request.Command = property
	request.Parameter = val

	_, err := pr.SendRequest(request)

	return err
}

//--------------------------------------------------------------------------------------------------------------------//
// Low-Level Calls
//--------------------------------------------------------------------------------------------------------------------//

func (pr *PJProjector) SendRequest(request PJRequest) (*PJResponse, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}

	response, requestError := pr.sendRawRequest(request)
	if requestError != nil {
		return nil, requestError
	}

	return response, nil
}

// sendRawRequest performs the request.
//
// Normally only one connection is required.
//
// Some PJLink Class 2 projectors may send:
//
//	%2LKUP=AA:BB:CC:DD:EE:FF
//
// and then close the TCP connection before sending the response to the
// requested command.
//
// In that specific case we reconnect once and repeat the original command.
func (pr *PJProjector) sendRawRequest(request PJRequest) (*PJResponse, error) {
	var lastErr error

	for attempt := 0; attempt < 2; attempt++ {
		resp, retry, err := pr.sendRawRequestOnce(request)

		if err == nil {
			return resp, nil
		}

		lastErr = err

		if !retry {
			return resp, err
		}

		time.Sleep(200 * time.Millisecond)
	}

	return nil, lastErr
}

func (pr *PJProjector) sendRawRequestOnce(
	request PJRequest,
) (*PJResponse, bool, error) {

	// Establish TCP connection with PJLink device.
	connection, connectionError := pr.connectToPJLink()
	if connectionError != nil {
		return nil, false, connectionError
	}

	defer connection.Close()

	// Timeout for complete PJLink exchange.
	if err := connection.SetDeadline(
		time.Now().Add(10 * time.Second),
	); err != nil {
		return nil, false, errors.New(
			"failed to set PJLink connection deadline: " + err.Error(),
		)
	}

	// PJLink messages end with carriage return: '\r'.
	//
	// If '\r' has not arrived yet, Scanner must request more network data.
	onCarriageReturn := func(
		data []byte,
		atEOF bool,
	) (
		advance int,
		token []byte,
		err error,
	) {
		for i := 0; i < len(data); i++ {
			if data[i] == '\r' {
				return i + 1, data[:i], nil
			}
		}

		if atEOF {
			if len(data) == 0 {
				return 0, nil, nil
			}

			return len(data), data, nil
		}

		// No complete PJLink line yet.
		// Ask Scanner to read more data.
		return 0, nil, nil
	}

	scanner := bufio.NewScanner(connection)
	scanner.Split(onCarriageReturn)

	//----------------------------------------------------------------------------------------------------------------//
	// Read greeting
	//----------------------------------------------------------------------------------------------------------------//

	// Expected:
	//
	//	PJLINK 0
	//
	// or:
	//
	//	PJLINK 1 XXXXXXXX

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, false, errors.New(
				"failed to read PJLink greeting: " + err.Error(),
			)
		}

		return nil, false, errors.New(
			"PJLink connection closed before greeting",
		)
	}

	challengeRaw := strings.Trim(
		scanner.Text(),
		"\x00 \t\r\n",
	)
	challenge := strings.Fields(challengeRaw)

	if len(challenge) < 2 {
		return nil, false, errors.New(
			"invalid PJLink greeting: " + challengeRaw,
		)
	}

	if challenge[0] != "PJLINK" {
		return nil, false, errors.New(
			"invalid PJLink greeting: " + challengeRaw,
		)
	}

	seed := pr.checkAuthentication(challenge)

	if challenge[1] == "1" && seed == "" {
		return nil, false, errors.New(
			"invalid PJLink authentication challenge: " + challengeRaw,
		)
	}

	//----------------------------------------------------------------------------------------------------------------//
	// Build and send command
	//----------------------------------------------------------------------------------------------------------------//

	stringCommand := request.toRaw(
		seed,
		pr.Password,
	)

	commandBytes := []byte(stringCommand)

	n, err := connection.Write(commandBytes)
	if err != nil {
		return nil, false, errors.New(
			"failed to send PJLink command: " + err.Error(),
		)
	}

	if n != len(commandBytes) {
		return nil, false, errors.New(
			"failed to send complete PJLink command",
		)
	}

	expectedClass := strconv.Itoa(request.Class)
	expectedCommand := request.Command

	gotLKUP := false

	//----------------------------------------------------------------------------------------------------------------//
	// Read response
	//----------------------------------------------------------------------------------------------------------------//

	for scanner.Scan() {
		rawResponse := strings.Trim(
			scanner.Text(),
			"\x00 \t\r\n",
		)

		if rawResponse == "" {
			continue
		}

		// PJLink authentication failure.
		if strings.Contains(rawResponse, "ERRA") {
			resp := NewPJResponse()

			err := resp.Parse(rawResponse)
			if err != nil {
				return resp, false, err
			}

			return resp, false, errors.New(
				"PJLink authentication error",
			)
		}

		// Normal PJLink response examples:
		//
		//	%1POWR=1
		//	%1POWR=0
		//	%1AVMT=OK
		//	%2LKUP=D0:D9:4F:E5:BB:67
		//
		// Minimum valid response structure:
		//
		//	%1XXXX=
		if len(rawResponse) < 7 {
			continue
		}

		if rawResponse[0] != '%' {
			continue
		}

		if rawResponse[6] != '=' {
			continue
		}

		resp := NewPJResponse()

		err := resp.Parse(rawResponse)
		if err != nil {
			return resp, false, err
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Unsolicited Class 2 LKUP
		//----------------------------------------------------------------------------------------------------------------//

		if resp.Class == "2" && resp.Command == "LKUP" {
			gotLKUP = true

			// Ignore it and continue waiting for our actual response.
			continue
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Other unsolicited PJLink message
		//----------------------------------------------------------------------------------------------------------------//

		if resp.Class != expectedClass ||
			resp.Command != expectedCommand {

			continue
		}

		//----------------------------------------------------------------------------------------------------------------//
		// This is the actual response to our command.
		//----------------------------------------------------------------------------------------------------------------//

		return resp, false, nil
	}

	//----------------------------------------------------------------------------------------------------------------//
	// Scanner stopped
	//----------------------------------------------------------------------------------------------------------------//

	if err := scanner.Err(); err != nil {
		return nil, false, errors.New(
			"failed to read PJLink response: " + err.Error(),
		)
	}

	// Special behaviour observed on some projectors:
	//
	//	%2LKUP=...
	//	EOF
	//
	// Request one reconnect/retry.
	if gotLKUP {
		return nil, true, errors.New(
			"PJLink connection closed after LKUP",
		)
	}

	return nil, false, errors.New(
		"PJLink connection closed before expected response",
	)
}

//--------------------------------------------------------------------------------------------------------------------//
// Connection
//--------------------------------------------------------------------------------------------------------------------//

// attempts to establish a TCP socket with the specified IP:port
func (pr *PJProjector) connectToPJLink() (net.Conn, error) {
	protocol := "tcp"
	timeout := 10

	connection, connectionError := net.DialTimeout(
		protocol,
		net.JoinHostPort(
			pr.Address,
			pr.Port,
		),
		time.Duration(timeout)*time.Second,
	)

	if connectionError != nil {
		return connection, errors.New(
			"failed to establish a connection with pjlink device. error msg: " +
				connectionError.Error(),
		)
	}

	return connection, nil
}

//--------------------------------------------------------------------------------------------------------------------//
// Authentication
//--------------------------------------------------------------------------------------------------------------------//

// check if this Projector uses authentication.
// If so return the seed.
// Otherwise return an empty string.
func (pr *PJProjector) checkAuthentication(response []string) string {
	if len(response) < 2 {
		return ""
	}

	if response[0] != "PJLINK" {
		return ""
	}

	switch response[1] {
	case "0":
		// Authentication disabled.
		return ""

	case "1":
		// Authentication enabled.
		if len(response) < 3 {
			return ""
		}

		return response[2]
	}

	return ""
}
