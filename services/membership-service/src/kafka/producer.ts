import { Kafka, Producer, logLevel } from "kafkajs";

const kafka = new Kafka({
  clientId: "membership-service",
  brokers: (process.env.KAFKA_BROKERS ?? "localhost:9092").split(","),
  // In production: SSL + SASL/SCRAM-SHA-512 (zero-trust Kafka)
  // ssl: true,
  // sasl: { mechanism: 'scram-sha-512', username: ..., password: ... },
  logLevel: logLevel.WARN,
  retry: {
    initialRetryTime: 300,
    retries: 8,
  },
});

let producer: Producer | null = null;

export async function getProducer(): Promise<Producer> {
  if (!producer) {
    producer = kafka.producer({
      allowAutoTopicCreation: false,
      transactionTimeout: 30000,
    });
    await producer.connect();
  }
  return producer;
}

export async function publishMemberProvisioned(payload: {
  memberId: string;
  issuerId: string;
  tier: string;
  status: string;
  visitLimit: number;
  timestamp: string;
}): Promise<void> {
  const p = await getProducer();
  await p.send({
    topic: "membership.provisioned",
    messages: [
      {
        key: payload.memberId,
        value: JSON.stringify({
          eventType: "membership.provisioned",
          ...payload,
        }),
        headers: {
          "content-type": "application/json",
          source: "membership-service",
        },
      },
    ],
  });
}

export async function publishMemberStatusChanged(payload: {
  memberId: string;
  oldStatus: string;
  newStatus: string;
  actor: string;
  timestamp: string;
}): Promise<void> {
  const p = await getProducer();
  await p.send({
    topic: "membership.provisioned",
    messages: [
      {
        key: payload.memberId,
        value: JSON.stringify({
          eventType: "membership.status_changed",
          ...payload,
        }),
      },
    ],
  });
}

export async function disconnectProducer(): Promise<void> {
  if (producer) {
    await producer.disconnect();
    producer = null;
  }
}
