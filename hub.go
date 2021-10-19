package main

import (
	"log"

	"github.com/streadway/amqp"
)

type Hub struct {
	clients map[*Client]bool
	broadcast chan []byte
	register chan *Client
	unregister chan *Client

    amqpConn *amqp.Connection
    queueName string
}

func NewHub(amqpUrl string, queueName string) *Hub {
    conn, err := amqp.Dial(amqpUrl)
    if err != nil {
        log.Fatal(err)
    }
 
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
        amqpConn: conn,
        queueName: queueName,
	}
}

func (h *Hub) runAmqpConsumer() {
    channel, err := h.amqpConn.Channel()
    if err != nil {
        log.Println("Failed to open a channel", err)
        return
    }
    defer channel.Close()

    queue, err := channel.QueueDeclare(
        h.queueName, // name
        false,   // durable
        false,   // delete when unused
        false,   // exclusive
        false,   // no-wait
        nil,     // arguments
    )
    if err != nil {
        log.Println("Failed to declare a queue")
        return
    }

    msgs, err := channel.Consume(
        queue.Name, // queue
        "",     // consumer
        true,   // auto-ack
        false,  // exclusive
        false,  // no-local
        false,  // no-wait
        nil,    // args
    )
    if err != nil {
        log.Println("Failed to register a consumer", err)
        return
    }

    for d := range msgs {
        h.broadcast <- d.Body
    }
}

func (h *Hub) run() {
    go h.runAmqpConsumer()
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}
