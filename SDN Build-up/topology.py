from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."
        firsthost = self.addHost( 'h1' )
        secondhost = self.addHost( 'h2' )
        thirdhost=self.addHost('h3')
        forthhost=self.addHost('h4')
        fifthhost=self.addHost('h5')
        sixthhost=self.addHost('h6')

        firstswitch = self.addSwitch( 's1' )
        secondswitch = self.addSwitch( 's2' )
        thirdswitch=self.addSwitch('s3')
        forthswitch=self.addSwitch('s4')
        # Add links
        self.addLink(firstswitch,secondswitch,bw=1000,loss=5)
        self.addLink(secondswitch,thirdswitch,bw=1000,loss=5)
        self.addLink(thirdswitch,forthswitch,bw=1000,loss=5)

        self.addLink(firstswitch,firsthost,bw=100)
        self.addLink(firstswitch,secondhost,bw=100)
        self.addLink(secondswitch,thirdhost,bw=100)
        self.addLink(thirdswitch,forthhost,bw=100)
        self.addLink(forthswitch,fifthhost,bw=100)
        self.addLink(forthswitch,sixthhost,bw=100)

topos = { 'mytopo': ( lambda: MyTopo() ) }
