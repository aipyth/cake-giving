package main

import (
	"log"
	"sync"

	"github.com/streadway/amqp"
)

type Publisher struct {
    QueueName string
    messages chan string
    nWorkers uint
    closeChan chan int
    amqpUrl string
}

func NewPublisher(amqpUrl string, queueName string, nWorkers uint) *Publisher {
    return &Publisher{
        QueueName: queueName,
        messages: make(chan string),
        nWorkers: nWorkers,
        amqpUrl: amqpUrl,
    }
}

func (p *Publisher) runWorkers() {
    conn, err := amqp.Dial(p.amqpUrl)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    ch, err := conn.Channel()
    if err != nil {
        log.Fatal(err)
    }
    defer ch.Close()

    q, err := ch.QueueDeclare(
        p.QueueName,
        false,   // durable
        false,   // delete when unused
        false,   // exclusive
        false,   // no-wait
        nil,     // arguments
    )
    if err != nil {
        log.Println(err)
        return
    }

    wg := &sync.WaitGroup{}
    wg.Add(int(p.nWorkers))

    for i := 0; i < int(p.nWorkers); i++ {
        go func() {
            defer wg.Done()
            for {
                select {
                case body := <- p.messages:
                    err = ch.Publish(
                        "",     // exchange
                        q.Name, // routing key
                        false,  // mandatory
                        false,  // immediate
                        amqp.Publishing {
                            ContentType: "text/plain",
                            Body:        []byte(body),
                        },
                    )
                    if err != nil {
                        log.Fatal("Failed to publish a message", err)
                    }
                case <-p.closeChan:
                    return
                }
            }
        }()
    }

    wg.Wait()
}

func (p *Publisher) Close() {
    for i := 0; i < int(p.nWorkers); i++ {
        p.closeChan <- i
    }
}

func (p *Publisher) Publish(message string) {
    p.messages <- message
}

