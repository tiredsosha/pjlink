package pjlink

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
// Functional Calls
//--------------------------------------------------------------------------------------------------------------------//

//--------------------------------------------------------------------------------------------------------------------//
// Power
//--------------------------------------------------------------------------------------------------------------------//

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
	request := PJRequest{
		Class:     1,
		Command:   property,
		Parameter: "?",
	}

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
	request := PJRequest{
		Class:     1,
		Command:   property,
		Parameter: "?",
	}

	resp, err := pr.SendRequest(request)
	if err != nil {
		return []string{}, err
	}

	return resp.Response, nil
}

func (pr *PJProjector) SetProperty(property string, val string) error {
	request := PJRequest{
		Class:     1,
		Command:   property,
		Parameter: val,
	}

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

	return pr.sendRawRequest(request)
}

//--------------------------------------------------------------------------------------------------------------------//
// PJLink line reader
//--------------------------------------------------------------------------------------------------------------------//

// readPJLinkLine reads one PJLink message terminated by '\r'.
//
// Some projectors pad their TCP packets with NUL bytes:
//
//	PJLINK 0\r\x00\x00\x00...
//	%2LKUP=...\r\x00\x00...
//	%1POWR=1\r\x00\x00...
//
// This function removes that padding and returns only the actual PJLink line.
func readPJLinkLine(reader *bufio.Reader) (string, error) {
	for {
		raw, err := reader.ReadString('\r')

		/*
			ReadString can return both data and io.EOF.

			If data exists, process it first.
		*/
		if len(raw) > 0 {
			// Remove carriage return.
			raw = strings.TrimSuffix(raw, "\r")

			// Remove NUL padding and normal whitespace
			// from both sides.
			raw = strings.Trim(
				raw,
				"\x00 \t\r\n",
			)

			if raw != "" {
				return raw, nil
			}
		}

		if err != nil {
			return "", err
		}
	}
}

//--------------------------------------------------------------------------------------------------------------------//
// Raw request
//--------------------------------------------------------------------------------------------------------------------//

func (pr *PJProjector) sendRawRequest(request PJRequest) (*PJResponse, error) {
	connection, err := pr.connectToPJLink()
	if err != nil {
		return nil, err
	}
	defer connection.Close()

	// Maximum time for the complete exchange.
	err = connection.SetDeadline(
		time.Now().Add(10 * time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to set PJLink connection deadline: %w",
			err,
		)
	}

	reader := bufio.NewReader(connection)

	//----------------------------------------------------------------------------------------------------------------//
	// Greeting
	//----------------------------------------------------------------------------------------------------------------//

	/*
		Normal projectors:

			PJLINK 0

		Password protected:

			PJLINK 1 XXXXXXXX

		Your projector actually sends something like:

			PJLINK 0\r
			\x00\x00\x00...

		readPJLinkLine() removes that padding.
	*/

	greeting, err := readPJLinkLine(reader)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read PJLink greeting: %w",
			err,
		)
	}

	challenge := strings.Fields(greeting)

	if len(challenge) < 2 {
		return nil, fmt.Errorf(
			"invalid PJLink greeting: %q",
			greeting,
		)
	}

	if challenge[0] != "PJLINK" {
		return nil, fmt.Errorf(
			"invalid PJLink greeting: %q",
			greeting,
		)
	}

	if challenge[1] != "0" && challenge[1] != "1" {
		return nil, fmt.Errorf(
			"invalid PJLink authentication mode: %q",
			greeting,
		)
	}

	seed := pr.checkAuthentication(challenge)

	if challenge[1] == "1" && seed == "" {
		return nil, fmt.Errorf(
			"invalid PJLink authentication challenge: %q",
			greeting,
		)
	}

	//----------------------------------------------------------------------------------------------------------------//
	// Build command
	//----------------------------------------------------------------------------------------------------------------//

	stringCommand := request.toRaw(
		seed,
		pr.Password,
	)

	commandBytes := []byte(stringCommand)

	//----------------------------------------------------------------------------------------------------------------//
	// Send command
	//----------------------------------------------------------------------------------------------------------------//

	n, err := connection.Write(commandBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to send PJLink command: %w",
			err,
		)
	}

	if n != len(commandBytes) {
		return nil, fmt.Errorf(
			"failed to send complete PJLink command: wrote %d/%d bytes",
			n,
			len(commandBytes),
		)
	}

	expectedClass := strconv.Itoa(request.Class)
	expectedCommand := request.Command

	//----------------------------------------------------------------------------------------------------------------//
	// Read responses
	//----------------------------------------------------------------------------------------------------------------//

	/*
		Normal projector:

			-> %1POWR ?
			<- %1POWR=1

		Your projector:

			-> %1POWR ?

			<- %2LKUP=D0:D9:4F:E5:BB:67
			   + lots of NUL bytes

			<- %1POWR=1
			   + lots of NUL bytes

		We ignore responses belonging to other commands and continue
		until the requested command arrives.
	*/

	for {
		rawResponse, err := readPJLinkLine(reader)

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New(
					"PJLink connection closed before expected response",
				)
			}

			return nil, fmt.Errorf(
				"failed to read PJLink response: %w",
				err,
			)
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Authentication failure
		//----------------------------------------------------------------------------------------------------------------//

		if strings.Contains(rawResponse, "ERRA") {
			return nil, errors.New(
				"Incorrect password",
			)
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Validate basic format
		//----------------------------------------------------------------------------------------------------------------//

		/*
			Minimum:

				%1POWR=

			Indexes:

				0  %
				1  class
				2  P
				3  O
				4  W
				5  R
				6  =
		*/

		if len(rawResponse) < 7 {
			continue
		}

		if rawResponse[0] != '%' {
			continue
		}

		if rawResponse[6] != '=' {
			continue
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Parse response
		//----------------------------------------------------------------------------------------------------------------//

		resp := NewPJResponse()

		err = resp.Parse(rawResponse)
		if err != nil {
			return resp, err
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Is this response for our command?
		//----------------------------------------------------------------------------------------------------------------//

		if resp.Class != expectedClass ||
			resp.Command != expectedCommand {

			/*
				Example:

					expected:
						Class   = 1
						Command = POWR

					received:
						Class   = 2
						Command = LKUP

				This is an unsolicited PJLink message.
				Ignore it.
			*/

			continue
		}

		//----------------------------------------------------------------------------------------------------------------//
		// Correct response
		//----------------------------------------------------------------------------------------------------------------//

		return resp, nil
	}
}

//--------------------------------------------------------------------------------------------------------------------//
// Connection
//--------------------------------------------------------------------------------------------------------------------//

func (pr *PJProjector) connectToPJLink() (net.Conn, error) {
	protocol := "tcp"
	timeout := 10 * time.Second

	connection, err := net.DialTimeout(
		protocol,
		net.JoinHostPort(
			pr.Address,
			pr.Port,
		),
		timeout,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to establish a connection with pjlink device: %w",
			err,
		)
	}

	return connection, nil
}

//--------------------------------------------------------------------------------------------------------------------//
// Authentication
//--------------------------------------------------------------------------------------------------------------------//

// checkAuthentication checks whether the projector requires authentication.
//
// PJLINK 0
//	-> no authentication.
//
// PJLINK 1 XXXXXXXX
//	-> XXXXXXXX is the authentication seed.
func (pr *PJProjector) checkAuthentication(response []string) string {
	if len(response) < 2 {
		return ""
	}

	if response[0] != "PJLINK" {
		return ""
	}

	switch response[1] {
	case "0":
		return ""

	case "1":
		if len(response) < 3 {
			return ""
		}

		return response[2]
	}

	return ""
}
