## Inter-component communication

### Messages

We'll call "message" to each data unit that each component (managers and agents) exchanges between them.

Kinds of messages:

<dl>
  <dt>Event message</dt>
  <dd>An event is a message that indicates that something happened in the agent. It means a change in the agent state. Logs and results of commands are examples of event messages. They may become alerts.</dd>
  <dt>State message</dt>
  <dd>These messages report the state of the agent. They are related to system inventory and results of scans, among others. They won't become alerts.</dd>
  <dt>Control message<dt>
  <dd>They are part of the protocol of several components between the manager and the agent. Control messages request an action. Notification payloads, WPK files transmission/execution requests, Active Response messages, remote configuration requests, and database synchronization verification messages belong to this kind of messages.</dd>
</dl>
