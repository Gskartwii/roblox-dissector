package peer

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/bits"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gskartwii/roblox-dissector/datamodel"
	"github.com/olebedev/emitter"
	"github.com/pierrec/xxHash/xxHash32"
	"github.com/robloxapi/rbxfile"
)

type InstanceEmitterBinding struct {
	Instance *datamodel.Instance
	Binding  <-chan emitter.Event
}

var LauncherStatuses = [...]string{
	"Wait",
	"Wait (2)",
	"Success",
	"Maintenance",
	"Error",
	"Game ended",
	"Game is full",
	"Roblox is updating",
	"Requesting a server",
	"Unknown 9",
	"User left",
	"Game blocked on this platform",
	"Unauthorized",
}

type placeLauncherResponse struct {
	JobId                string
	Status               int
	JoinScriptUrl        string
	AuthenticationUrl    string
	AuthenticationTicket string
}
type JoinAshxResponse struct {
	ClientTicket          string
	NewClientTicket       string
	SessionId             string
	MachineAddress        string
	ServerPort            uint16
	UserId                int64
	UserName              string
	CharacterAppearance   string
	CharacterAppearanceId int64
	PingInterval          int
	AccountAge            int
}

type SecurityHandler interface {
	GenerateIdResponse(challenge uint32) uint32
	PatchTicketPacket(*Packet8ALayer)
	GenerateTicketHash(ticket string) uint32
	OsPlatform() string
	UserAgent() string
}
type SecuritySettings struct {
	rakPassword   []byte
	goldenHash    uint32
	securityKey   string
	dataModelHash string
	osPlatform    string
	userAgent     string
}
type Windows10SecuritySettings struct {
	SecuritySettings
}

type JoinData struct {
	RawJoinData           string
	CharacterAppearance   string
	GameChatType          string
	FollowUserId          int64
	AccountAge            int32
	SuperSafeChat         bool
	VrDevice              string
	MembershipType        string
	Locale2Id             string
	UserName              string
	IsTeleportedIn        bool
	LocaleId              string
	CharacterAppearanceId int64
	UserId                int64
}

func (d JoinData) JSON() ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&d)
	// drop trailing newline
	return buffer.Bytes()[:buffer.Len()-1], err
}

type CustomClient struct {
	PacketLogicHandler
	Address               net.UDPAddr
	ServerAddress         net.UDPAddr
	clientTicket          string
	sessionId             string
	PlayerId              int64
	UserName              string
	characterAppearance   string
	characterAppearanceId int64
	PlaceId               uint32
	httpClient            *http.Client
	GUID                  uint64
	BrowserTrackerId      uint64
	GenderId              uint8
	IsPartyLeader         bool
	AccountAge            int

	JoinDataObject JoinData

	SecuritySettings   SecurityHandler
	Logger             *log.Logger
	LocalPlayer        *datamodel.Instance
	timestamp2Index    uint64
	InstanceDictionary *datamodel.InstanceDictionary

	writerBinding         <-chan emitter.Event
	rootLayerPatchBinding <-chan emitter.Event
}

func (myClient *CustomClient) ReadPacket(buf []byte) {
	layers := &PacketLayers{
		Root: RootLayer{
			Source:      &myClient.ServerAddress,
			Destination: &myClient.Address,
			FromServer:  true,
		},
	}
	myClient.ConnectedPeer.ReadPacket(buf, layers)
}

func NewCustomClient(ctx context.Context) *CustomClient {
	rand.Seed(time.Now().UnixNano())
	context := NewCommunicationContext()

	client := &CustomClient{
		httpClient: &http.Client{},
		GUID:       rand.Uint64(),

		PacketLogicHandler: newPacketLogicHandler(context, false),
		InstanceDictionary: datamodel.NewInstanceDictionary(),
	}

	client.RunningContext = ctx
	client.createWriter()
	client.bindDefaultHandlers()

	return client
}

func (myClient *CustomClient) GetLocalPlayer() (*datamodel.Instance, error) { // may yield! do not call from main thread
	return myClient.DataModel.WaitForChild(myClient.RunningContext, "Players", myClient.UserName)
}

// call this asynchronously! it will wait a lot
func (myClient *CustomClient) setupStalk() {
	err := myClient.StalkPlayer("gskw")
	if err != nil {
		myClient.Logger.Printf("Stalk error: %s\n", err.Error())
	}
}

// call this asynchronously! it will wait a lot
func (myClient *CustomClient) setupChat() error {
	ctx, cancelChat := context.WithCancel(myClient.RunningContext)
	defer cancelChat()

	chatEvents, err := myClient.DataModel.WaitForChild(ctx, "ReplicatedStorage", "DefaultChatSystemChatEvents")
	if err != nil {
		return err
	}
	getInitDataRequest, err := chatEvents.WaitForChild(ctx, "GetInitDataRequest")
	if err != nil {
		return err
	}

	initData, err := myClient.InvokeRemote(getInitDataRequest, []rbxfile.Value{})
	if err != nil {
		return err
	}
	data := initData[0].(datamodel.ValueDictionary)
	channels := data["Channels"].(datamodel.ValueArray)
	var channelNames strings.Builder
	for _, channel := range channels {
		channelNames.WriteString(string(channel.(datamodel.ValueArray)[0].(rbxfile.ValueString)))
		channelNames.WriteString(", ")
	}
	myClient.Logger.Printf("SYSTEM: Channels available: %s\n", channelNames.String()[:channelNames.Len()-2])

	messageFiltered, err := chatEvents.WaitForChild(ctx, "OnMessageDoneFiltering")
	newFilteredMessageEvtChan := messageFiltered.EventEmitter.On("OnClientEvent")

	players := myClient.DataModel.FindService("Players")

	playerJoinEmitter := players.ChildEmitter.On("*")
	for _, player := range players.Children {
		myClient.Logger.Printf("SYSTEM: %s is here.\n", player.Name())
	}
	playerLeaveChan := make(chan *datamodel.Instance)
	playerLeaveBindings := list.New()

	for {
		select {
		case e, received := <-newFilteredMessageEvtChan:
			if !received {
				continue
			}
			message := e.Args[0].([]rbxfile.Value)
			dict := message[0].(datamodel.ValueTuple)[0].(datamodel.ValueDictionary)
			myClient.Logger.Printf("<%s (%s)> %s\n", dict["FromSpeaker"].(rbxfile.ValueString), dict["MessageType"].(rbxfile.ValueString), dict["Message"].(rbxfile.ValueString))
		case joinEvent, received := <-playerJoinEmitter:
			if !received {
				continue
			}
			player := joinEvent.Args[0].(*datamodel.Instance)
			myClient.Logger.Printf("SYSTEM: %s has joined the game.\n", player.Name())
			go func(player *datamodel.Instance) {
				parentEmitter := player.PropertyEmitter.On("Parent")
				thisBinding := playerLeaveBindings.PushBack(InstanceEmitterBinding{Instance: player, Binding: parentEmitter})
				for newParent := range parentEmitter {
					if newParent.Args[0].(*datamodel.Instance) == nil {
						playerLeaveBindings.Remove(thisBinding)
						player.PropertyEmitter.Off("Parent", parentEmitter)
						playerLeaveChan <- player
						return
					}
				}
			}(player)
		case player := <-playerLeaveChan:
			myClient.Logger.Printf("SYSTEM: %s has left the game.\n", player.Name())
		case <-myClient.RunningContext.Done():
			players.ChildEmitter.Off("*", playerJoinEmitter)
			for thisBind := playerLeaveBindings.Front(); thisBind != nil; thisBind = thisBind.Next() {
				bind := thisBind.Value.(InstanceEmitterBinding)
				bind.Instance.PropertyEmitter.Off("Parent", bind.Binding)
			}
			return nil
		}
	}
}

func (myClient *CustomClient) SendChat(message string, toPlayer string, channel string) error {
	if channel == "" {
		channel = "All" // assume default channel
	}

	remote, err := myClient.DataModel.WaitForChild(myClient.RunningContext, "ReplicatedStorage", "DefaultChatSystemChatEvents", "SayMessageRequest")
	if err != nil {
		return err
	}
	if toPlayer != "" {
		message = "/w " + toPlayer + " " + message
	}

	myClient.FireRemote(remote, rbxfile.ValueString(message), rbxfile.ValueString(channel))
	return nil
}

func (myClient *CustomClient) joinWithJoinScript(url string, cookies []*http.Cookie) error {
	joinScriptRequest, err := http.NewRequest("GET", url, nil)
	robloxCommClient := myClient.httpClient
	if err != nil {
		return err
	}

	for _, cook := range cookies {
		if x, _ := joinScriptRequest.Cookie(cook.Name); x == nil {
			joinScriptRequest.AddCookie(cook)
		}
	}
	joinScriptRequest.Header.Set("Cookie", joinScriptRequest.Header.Get("Cookie")+"; RBXAppDeviceIdentifier=AppDeviceIdentifier=ROBLOX UWP")

	resp, err := robloxCommClient.Do(joinScriptRequest)
	if err != nil {
		return err
	}
	body := resp.Body

	// Discard rbxsig by reading until newline
	char := make([]byte, 1)
	_, err = body.Read(char)
	for err == nil && char[0] != 0x0A {
		_, err = body.Read(char)
	}

	if err != nil {
		return err
	}

	bodyBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}
	body.Close()

	var jsResp JoinAshxResponse
	err = json.Unmarshal(bodyBytes, &jsResp)
	if err != nil {
		return err
	}
	myClient.characterAppearance = jsResp.CharacterAppearance
	myClient.characterAppearanceId = jsResp.CharacterAppearanceId
	myClient.clientTicket = jsResp.ClientTicket
	myClient.sessionId = jsResp.SessionId
	myClient.PlayerId = jsResp.UserId
	myClient.UserName = jsResp.UserName
	myClient.pingInterval = jsResp.PingInterval
	myClient.AccountAge = jsResp.AccountAge

	err = json.Unmarshal(bodyBytes, &myClient.JoinDataObject)
	if err != nil {
		return err
	}
	myClient.JoinDataObject.LocaleId = "en-us"

	addrp, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", jsResp.MachineAddress, jsResp.ServerPort))
	if err != nil {
		return err
	}

	myClient.Logger.Println("Connecting to", jsResp.MachineAddress)

	myClient.ServerAddress = *addrp
	return myClient.rakConnect()
}

func (myClient *CustomClient) joinWithPlaceLauncher(url string, cookies []*http.Cookie) error {
	var plResp placeLauncherResponse
	var resp *http.Response
	robloxCommClient := myClient.httpClient
	for i := 0; i < 5; i++ {
		myClient.Logger.Println("requesting placelauncher", url, "attempt", i)
		placeLauncherRequest, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		placeLauncherRequest.Header.Set("User-Agent", myClient.SecuritySettings.UserAgent())
		for _, cookie := range cookies {
			placeLauncherRequest.AddCookie(cookie)
		}
		placeLauncherRequest.Header.Set("Cookie", placeLauncherRequest.Header.Get("Cookie")+"; RBXAppDeviceIdentifier=AppDeviceIdentifier=ROBLOX UWP")

		resp, err = robloxCommClient.Do(placeLauncherRequest)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&plResp)
		if err != nil {
			return err
		}
		if plResp.Status == 0 || plResp.Status == 1 { // status: wait
			myClient.Logger.Println("status=0 --> retrying after 5s")
			time.Sleep(time.Second * 5)
			continue
		} else if plResp.Status != 2 { // status: success
			return errors.New("PlaceLauncher failed to connnect, reason: " + LauncherStatuses[plResp.Status])
		}

		if plResp.JoinScriptUrl == "" {
			myClient.Logger.Println("joinscript failure, status", plResp.Status)
			return errors.New("couldn't get joinscripturl")
		} else {
			break
		}
	}

	for _, cook := range resp.Cookies() {
		cookies = append(cookies, cook)
	}

	return myClient.joinWithJoinScript(plResp.JoinScriptUrl, cookies)
}

func (myClient *CustomClient) ConnectWithAuthTicket(placeId uint32, ticket string) error {
	myClient.PlaceId = placeId
	robloxCommClient := myClient.httpClient
	negotiationRequest, err := http.NewRequest("POST", "https://www.roblox.com/Login/Negotiate.ashx?suggest="+ticket, nil)
	if err != nil {
		return err
	}

	negotiationRequest.Header.Set("Playercount", "0")
	negotiationRequest.Header.Set("Requester", "Client")
	negotiationRequest.Header.Set("User-Agent", myClient.SecuritySettings.UserAgent())
	negotiationRequest.Header.Set("Content-Length", "0")
	negotiationRequest.Header.Set("X-Csrf-Token", "")
	negotiationRequest.Header.Set("Rbxauthenticationnegotiation", "www.roblox.com")
	negotiationRequest.Header.Set("Host", "www.roblox.com")

	resp, err := robloxCommClient.Do(negotiationRequest)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 { // token verification failed
		negotiationRequest.Header.Set("X-Csrf-Token", resp.Header.Get("X-Csrf-Token"))
		myClient.Logger.Println("Set csrftoken:", resp.Header.Get("X-Csrf-Token"))

		resp, err = robloxCommClient.Do(negotiationRequest)
		if err != nil {
			return err
		}
		if resp.StatusCode == 403 {
			return errors.New("couldn't negotiate ticket: " + resp.Status)
		}
	}
	cookies := resp.Cookies()

	return myClient.joinWithPlaceLauncher(fmt.Sprintf("https://www.roblox.com/game/PlaceLauncher.ashx?request=RequestGame&browserTrackerId=%d&placeId=%d&isPartyLeader=false&genderId=%d", myClient.BrowserTrackerId, myClient.PlaceId, myClient.GenderId), cookies)
}

func (settings *SecuritySettings) UserAgent() string {
	return settings.userAgent
}
func (settings *SecuritySettings) OsPlatform() string {
	return settings.osPlatform
}

// Automatically fills in any needed hashes/key for Windows 10 clients
func Win10Settings() *Windows10SecuritySettings {
	settings := &Windows10SecuritySettings{}
	settings.userAgent = "Roblox/WinINet"
	settings.osPlatform = "Windows_Universal"
	return settings
}
func (settings *Windows10SecuritySettings) GenerateIdResponse(challenge uint32) uint32 {
	return (0xFFFFFFFF ^ (challenge - 0x664B2854)) - 0x1B460
}
func (settings *Windows10SecuritySettings) GenerateTicketHash(ticket string) uint32 {
	var ecxHash uint32
	initHash := xxHash32.Checksum([]byte(ticket), 1)
	initHash += 0x557BB5D7
	initHash = bits.RotateLeft32(initHash, 7)
	initHash -= 0x443921D5
	initHash *= 0x557BB5D7
	initHash = bits.RotateLeft32(initHash, -0xD)
	ecxHash = 0x443921D5 - initHash
	ecxHash ^= 0x443921D5
	ecxHash = bits.RotateLeft32(ecxHash, -0x11)
	ecxHash -= 0x11429402
	ecxHash = bits.RotateLeft32(ecxHash, -0x17)
	initHash = 0x11429402 - ecxHash
	initHash = bits.RotateLeft32(initHash, -0x1D)
	initHash ^= 0x443921D5
	initHash = -initHash

	return initHash
}
func (settings *Windows10SecuritySettings) PatchTicketPacket(packet *Packet8ALayer) {
	packet.SecurityKey = "2e427f51c4dab762fe9e3471c6cfa1650841723b!b1205bf4c3bb3bdbf245f3654cee567a\x0E"
	packet.GoldenHash = 0xC001CAFE
	packet.DataModelHash = "ios,ios"
	packet.Platform = settings.osPlatform
	packet.TicketHash = settings.GenerateTicketHash(packet.ClientTicket)
}

func (myClient *CustomClient) dial() {
	maxLength := 1492
	dataLength := 0x3C
	connreqpacket := &Packet05Layer{ProtocolVersion: 5}
	go func() {
		for i := 0; i < 5; i++ {
			connreqpacket.MTUPaddingLength = maxLength - dataLength
			if myClient.Connected {
				myClient.Logger.Println("successfully dialed")
				return
			}
			myClient.WriteSimple(connreqpacket)
			select {
			case <-time.After(5 * time.Second):
			case <-myClient.RunningContext.Done():
				return
			}
			if i > 2 {
				maxLength = 576
			}
		}
		myClient.Logger.Println("dial failed after 5 attempts")
	}()
}

func (myClient *CustomClient) mainReadLoop() error {
	buf := make([]byte, 1492)
	for {
		// this connection should be closed when the context expires
		// hence we don't need to select{} RunningContext.Done()
		n, _, err := myClient.Connection.ReadFromUDP(buf)
		if err != nil {
			myClient.Logger.Println("fatal read err:", err.Error(), "read", n, "bytes")
			return err // a read error may be a sign that the connection was closed
			// hence we can't run this loop anymore; we would get infinitely many errors
		}

		myClient.ReadPacket(buf[:n])
	}
}

func (myClient *CustomClient) createWriter() {
	myClient.writerBinding = myClient.Output.On("udp", func(e *emitter.Event) {
		num, err := myClient.Connection.Write(e.Args[0].([]byte))
		if err != nil {
			fmt.Printf("Wrote %d bytes, err: %s\n", num, err.Error())
		}
	}, emitter.Void)
	myClient.rootLayerPatchBinding = myClient.DefaultPacketWriter.LayerEmitter.On("*", func(e *emitter.Event) {
		e.Args[0].(*PacketLayers).Root = RootLayer{
			FromClient:  true,
			Logger:      nil,
			Source:      &myClient.Address,
			Destination: &myClient.ServerAddress,
		}
	}, emitter.Void)
}

func (myClient *CustomClient) rakConnect() error {
	var err error
	addr := myClient.ServerAddress

	myClient.Connection, err = net.DialUDP("udp", nil, &addr)
	defer myClient.Connection.Close()
	if err != nil {
		return err
	}
	myClient.Address = *myClient.Connection.LocalAddr().(*net.UDPAddr)

	myClient.dial()
	myClient.startAcker()

	go myClient.setupChat() // needs to run async; does a lot of waiting for instances
	go myClient.setupStalk()

	return myClient.mainReadLoop()
}
