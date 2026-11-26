package quicx

// TraceOptions 控制 qlog 输出。
type TraceOptions struct {
	// Path 是输出目录，空表示不记录。
	Path string
	// Capacity 是单个文件的上限，单位 MB，零值使用默认值 384。
	Capacity int
}

// channelEvent 是 qlog 里的 quicx 层事件，用来把通道与传输层对上。
type channelEvent struct {
	Channel     uint32 `json:"channel"`
	Destination string `json:"destination,omitempty"`
	Length      int    `json:"length,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type sessionEvent struct {
	Reason string `json:"reason"`
}
