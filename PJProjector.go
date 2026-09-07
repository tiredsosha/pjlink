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
		// malformed command, don't send
		return nil, err
	}

	response, requestError := pr.sendRawRequest(request)
	if requestError != nil {
		return nil, requestError
	}

	return response, nil
}

func (pr *PJProjector) sendRawRequest(request PJRequest) (*PJResponse, error) {
	// Establish TCP connection with PJLink device.
	connection, connectionError := pr.connectToPJLink()

	if connectionError != nil {
		return nil, connectionError
	}

	defer connection.Close()

	// Set timeout for the whole PJLink exchange.
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, errors.New(
			"failed to set PJLink connection deadline: " + err.Error(),
		)
	}

	/*
		Split PJLink messages by carriage return.

		IMPORTANT:
		If '\r' hasn't arrived yet, Scanner must request more data.

		The old implementation returned bufio.ErrFinalToken here.
		That could make Scanner treat a partial TCP packet as a complete
		PJLink message.
	*/
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

		// No '\r' yet.
		// Tell Scanner to read more data.
		return 0, nil, nil
	}

	scanner := bufio.NewScanner(connection)
	scanner.Split(onCarriageReturn)

	// -------------------------------------------------------------------------
	// Read PJLink greeting
	//
	// Normally:
	//
	// PJLINK 0
	//
	// or:
	//
	// PJLINK 1 XXXXXXXX
	// -------------------------------------------------------------------------

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, errors.New(
				"failed to read PJLink greeting: " + err.Error(),
			)
		}

		return nil, errors.New(
			"PJLink connection closed before greeting",
		)
	}

	challengeRaw := strings.TrimSpace(scanner.Text())
	challenge := strings.Fields(challengeRaw)

	if len(challenge) < 2 || challenge[0] != "PJLINK" {
		return nil, errors.New(
			"invalid PJLink greeting: " + challengeRaw,
		)
	}

	seed := pr.checkAuthentication(challenge)

	// If authentication is enabled but the challenge is malformed,
	// do not continue with an invalid request.
	if challenge[1] == "1" && seed == "" {
		return nil, errors.New(
			"invalid PJLink authentication challenge: " + challengeRaw,
		)
	}

	stringCommand := request.toRaw(
		seed,
		pr.Password,
	)

	// -------------------------------------------------------------------------
	// Send command
	// -------------------------------------------------------------------------

	commandBytes := []byte(stringCommand)

	n, err := connection.Write(commandBytes)

	if err != nil {
		return nil, errors.New(
			"failed to send PJLink command: " + err.Error(),
		)
	}

	if n != len(commandBytes) {
		return nil, errors.New(
			"failed to send complete PJLink command",
		)
	}

	expectedClass := strconv.Itoa(request.Class)
	expectedCommand := request.Command

	// -------------------------------------------------------------------------
	// Read responses
	//
	// Normal projector:
	//
	//	%1POWR=1
	//
	// Some Class 2 projectors:
	//
	//	%2LKUP=D0:D9:4F:E5:BB:67
	//	%1POWR=1
	//
	// Therefore we keep reading until we receive the response belonging
	// to the command we sent.
	// -------------------------------------------------------------------------

	for scanner.Scan() {
		rawResponse := strings.TrimSpace(scanner.Text())

		if rawResponse == "" {
			continue
		}

		// Authentication error from projector.
		if strings.Contains(rawResponse, "ERRA") {
			resp := NewPJResponse()

			err := resp.Parse(rawResponse)
			if err != nil {
				return resp, err
			}

			return resp, errors.New("PJLink authentication error")
		}

		/*
			A valid command response looks like:

			%1POWR=1
			%1AVMT=OK
			%2LKUP=AA:BB:CC:DD:EE:FF

			Minimum structure:

			% C C C C C =

			0 1 2 3 4 5 6
		*/
		if len(rawResponse) < 7 {
			// Ignore unrelated/malformed asynchronous data.
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
			return resp, err
		}

		/*
			Ignore unsolicited PJLink Class 2 messages.

			Example:

			Expected:
			    Class   = 1
			    Command = POWR

			Received:
			    Class   = 2
			    Command = LKUP

			This is not our command response, so continue reading.
		*/
		if resp.Class != expectedClass ||
			resp.Command != expectedCommand {

			continue
		}

		// This is the response to our command.
		return resp, nil
	}

	// Scanner stopped.
	if err := scanner.Err(); err != nil {
		return nil, errors.New(
			"failed to read PJLink response: " + err.Error(),
		)
	}

	return nil, errors.New(
		"PJLink connection closed before expected response",
	)
}

// attempt to establish a TCP socket with the specified IP:port
// success: returns populated pjlinkConn struct and nil error
// failure: returns empty pjlinkConn and error
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

// check if this Projector uses authentication.
// If so return the given seed.
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
		// No authentication.
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
