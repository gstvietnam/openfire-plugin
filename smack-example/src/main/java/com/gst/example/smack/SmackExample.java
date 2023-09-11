package com.gst.example.smack;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.chat2.Chat;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.roster.RosterEntry;
import org.jivesoftware.smack.roster.SubscribeListener;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smackx.mam.MamManager;
import org.jxmpp.jid.EntityBareJid;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.stringprep.XmppStringprepException;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class SmackExample {

    private static final int WAITING_FOR_OPENFIRE_HANDLE_DATA = 2000;

    public void sampleUseCase() throws IOException, InterruptedException, XMPPException, SmackException {
        AbstractXMPPConnection cunglam = createConnection("cunglam", "123");
        AbstractXMPPConnection lamcung = createConnection("lamcung", "123");
        autoAcceptFriendRequest(lamcung);
        ChatManager chatManagerCungLam = createChat(cunglam);
        createChat(lamcung);
        EntityBareJid jid = JidCreate.entityBareFrom("lamcung@openfire-localhost");
        Chat chat = chatManagerCungLam.chatWith(jid);
        chat.send("Hello!");
        Roster roster = createFriendRequest(cunglam, jid);
        Thread.sleep(WAITING_FOR_OPENFIRE_HANDLE_DATA);
        printFriendList(roster);
        printFriendList(Roster.getInstanceFor(lamcung));
        cunglam.disconnect();
        lamcung.disconnect();
    }

    private Roster createFriendRequest(AbstractXMPPConnection from, EntityBareJid to) throws SmackException.NotLoggedInException, SmackException.NoResponseException, XMPPException.XMPPErrorException, SmackException.NotConnectedException, InterruptedException {
        Roster roster = Roster.getInstanceFor(from);
        roster.createItemAndRequestSubscription(to, null, null);
        return roster;
    }

    private void printFriendList(Roster roster) {
        System.out.println("print friend for: " + roster);
        Collection<RosterEntry> entries = roster.getEntries();
        for (RosterEntry entry : entries) {
            System.out.println("roster entry:" + entry);
        }
    }

    ChatManager createChat(AbstractXMPPConnection cunglam) {
        ChatManager chatManager = ChatManager.getInstanceFor(cunglam);
        chatManager.addIncomingListener((from, message, chat1)
                -> System.out.println("New message from " + from + ": " + message.getBody()));
        return chatManager;
    }

    AbstractXMPPConnection createConnection(String username, String password)
            throws SmackException, IOException, XMPPException, InterruptedException {
        XMPPTCPConnectionConfiguration config = XMPPTCPConnectionConfiguration.builder()
//                .enableDefaultDebugger()
                .setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
                .setUsernameAndPassword(username, password)
                .setXmppDomain("localhost")
                .setHost("localhost")
                .build();
        AbstractXMPPConnection connection = new XMPPTCPConnection(config);
        connection.connect(); //Establishes a connection to the server
        connection.login(); //Logs in
        return connection;
    }

    private void autoAcceptFriendRequest(AbstractXMPPConnection connection) {
        Roster.getInstanceFor(connection).addSubscribeListener((jid1, presence) -> {
            System.out.println("receive subscribe request from:" + jid1);
            return SubscribeListener.SubscribeAnswer.Approve;
        });
    }

    public List<Message> loadChatHistory(AbstractXMPPConnection connection) throws XMPPException.XMPPErrorException, InterruptedException, SmackException.NotConnectedException, SmackException.NotLoggedInException, SmackException.NoResponseException, XmppStringprepException {
        MamManager mamManager = MamManager.getInstanceFor(connection);
        Date endDate = Date.from(LocalDateTime.now().minusWeeks(1).atZone(ZoneId.systemDefault()).toInstant());
        MamManager.MamQueryArgs mamQueryArgs = MamManager.MamQueryArgs.builder()
                .limitResultsSince(endDate)
                .limitResultsToJid(JidCreate.entityBareFrom("lamcung@openfire-localhost"))
                .setResultPageSize(1000000000)
                .queryLastPage()
                .build();
        return mamManager.queryArchive(mamQueryArgs).getMessages();
    }
}
