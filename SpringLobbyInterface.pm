# Object-oriented Perl module implementing a callback-based interface to
# communicate with SpringRTS lobby server.
#
# Copyright (C) 2008-2024  Yann Riou <yaribzh@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

package SpringLobbyInterface;

use strict;

use Digest::MD5 "md5_base64";
use IO::Select;
use IO::Socket::INET;
use JSON::PP ();
use List::Util 'any';
use Storable "dclone";

use SimpleLog;
use SpringLobbyProtocol;

# Internal data ###############################################################

my $moduleVersion='0.54';

use constant { PROTOCOL_EXTENSIONS_PREFIX => '@PROTOCOL_EXTENSIONS@ ' };
use constant { PROTOCOL_EXTENSIONS_PREFIX_LENGTH => length(PROTOCOL_EXTENSIONS_PREFIX) };

our %commandHooks = (
  LOGIN => \&loginHook,
  OPENBATTLE => \&openBattleHook,
  JOINBATTLE => \&joinBattleHook,
  DISABLEUNITS => \&disableUnitsHandler,       #
  ENABLEUNITS => \&enableUnitsHandler,         #
  ENABLEALLUNITS => \&enableAllUnitsHandler,   # These commands aren't sent back to battle founder by legacy lobby server (TASServer)
  ADDSTARTRECT => \&addStartRectHandler,       #
  REMOVESTARTRECT => \&removeStartRectHandler, #
  UPDATEBOT => \&updateBotHook,
  FORCEALLYNO => \&forceAllyNoHook,
  FORCETEAMNO => \&forceTeamNoHook
);

our %commandHandlers = (
  TASSERVER => \&tasserverHandler,
  ACCEPTED => \&acceptedHandler,
  OK => \&okHandler,
  CLIENTIPPORT => \&clientIpPortHandler,
  JOINBATTLEREQUEST => \&joinBattleRequestHandler,
  ADDUSER => \&addUserHandler,
  REMOVEUSER => \&removeUserHandler,
  JOIN => \&joinHandler,
  CHANNELTOPIC => \&channelTopicHandler,
  CLIENTS => \&clientsHandler,
  JOINED => \&joinedHandler,
  LEFT => \&leftHandler,
  FORCELEAVECHANNEL => \&forceLeaveChannelHandler,
  OPENBATTLE => \&openBattleHandler,
  BATTLEOPENED => \&battleOpenedHandler,
  BATTLECLOSED => \&battleClosedHandler,
  JOINBATTLE => \&joinBattleHandler,
  JOINEDBATTLE => \&joinedBattleHandler,
  LEFTBATTLE => \&leftBattleHandler,
  UPDATEBATTLEINFO => \&updateBattleInfoHandler,
  CLIENTSTATUS => \&clientStatusHandler,
  CLIENTBATTLESTATUS => \&clientBattleStatusHandler,
  DISABLEUNITS => \&disableUnitsHandler,
  ENABLEUNITS => \&enableUnitsHandler,
  ENABLEALLUNITS => \&enableAllUnitsHandler,
  ADDBOT => \&addBotHandler,
  REMOVEBOT => \&removeBotHandler,
  UPDATEBOT => \&updateBotHandler,
  ADDSTARTRECT => \&addStartRectHandler,
  REMOVESTARTRECT => \&removeStartRectHandler,
  SETSCRIPTTAGS => \&setScriptTagsHandler,
  REMOVESCRIPTTAGS => \&removeScriptTagsHandler,
  SERVERMSG => \&serverMsgHandler,
);

my $tlsAvailable; # checked only when needed to avoid loading IO::Socket::SSL if not required

# Constructor #################################################################

sub new {
  my ($objectOrClass,%params) = @_;
  my $class = ref($objectOrClass) || $objectOrClass;
  my $p_conf = {
    serverHost => 'lobby.springrts.com',
    serverPort => 8200,
    timeout => 30,
    simpleLog => undef,
    inconsistencyHandler => undef,
    warnForUnhandledMessages => 1
  };
  foreach my $param (keys %params) {
    if(exists $p_conf->{$param}) {
      $p_conf->{$param}=$params{$param};
    }else{
      if(! (defined $p_conf->{simpleLog})) {
        $p_conf->{simpleLog}=SimpleLog->new(prefix => "[SpringLobbyInterface] ");
      }
      $p_conf->{simpleLog}->log("Ignoring invalid constructor parameter ($param)",2)
    }
  }
  if(! (defined $p_conf->{simpleLog})) {
    $p_conf->{simpleLog}=SimpleLog->new(prefix => "[SpringLobbyInterface] ");
  }

  my $self = {
    conf => $p_conf,
    lobbySock => undef,
    compatFlags => {},
    protocolExtensions => {},
    readBuffer => '',
    login => undef,
    serverParams => {},
    users => {},
    accounts => {},
    channels => {},
    battles => {},
    battle => {},
    runningBattle => {},
    callbacks => {},
    preCallbacks => {},
    pendingRequests => {},
    pendingResponses => {},
    openBattleModHash => 0,
    password => '*',
    lastSndTs => 0,
    lastRcvTs => 0,
    tlsCertifHash => undef,
    tlsServerIsAuthenticated => undef,
    performingTlsHandshake => undef,
  };

  bless ($self, $class);
  return $self;
}

# Accessors ###################################################################

sub getVersion {
  return $moduleVersion;
}

sub getLogin {
  my $self = shift;
  return $self->{login};
}

sub getUsers {
  my $self = shift;
  return dclone($self->{users});
}

sub getChannels {
  my $self = shift;
  return dclone($self->{channels});
}

sub getBattles {
  my $self = shift;
  return dclone($self->{battles});
}

sub getBattle {
  my $self = shift;
  return dclone($self->{battle});
}

sub getRunningBattle {
  my $self = shift;
  return dclone($self->{runningBattle});
}

# Marshallers/unmarshallers ###################################################

sub marshallPasswd { SpringLobbyProtocol::marshallPasswd($_[1]) }

sub marshallClientStatus { SpringLobbyProtocol::marshallClientStatus($_[1]) }

sub unmarshallClientStatus { SpringLobbyProtocol::unmarshallClientStatus($_[1]) }

sub marshallBattleStatus {
  return SpringLobbyProtocol::marshallBattleStatusEx($_[1]) if($_[0]{protocolExtensions}{'battleStatus:teams-8bit'});
  my @workaroundStrings;
  foreach my $f (qw'team id') {
    my $v=$_[1]{$f};
    push(@workaroundStrings,"$f=$v") if($v > 15);
  }
  my $res=SpringLobbyProtocol::marshallBattleStatus($_[1]);
  $res.='('.join(';',@workaroundStrings).')' if(@workaroundStrings);
  return $res;
}

sub unmarshallBattleStatus { $_[0]{protocolExtensions}{'battleStatus:teams-8bit'} ? SpringLobbyProtocol::unmarshallBattleStatusEx($_[1]) : SpringLobbyProtocol::unmarshallBattleStatus($_[1]) }

sub marshallColor { SpringLobbyProtocol::marshallColor($_[1]) }

sub unmarshallColor { SpringLobbyProtocol::unmarshallColor($_[1]) }

sub marshallCommand {
  my ($self,$p_unmarshalled)=@_;
  my $sl=$self->{conf}{simpleLog};
  my $marshalled = eval { SpringLobbyProtocol::marshallClientCommand($p_unmarshalled) };
  do { chomp($@); $sl->log("Unable to marshall command ($@)",1) } unless(defined $marshalled);
  return $marshalled;
}

sub unmarshallCommand {
  my ($self,$marshalled)=@_;
  my $sl=$self->{conf}{simpleLog};
  my ($r_cmd,$cmdId) = eval { SpringLobbyProtocol::unmarshallServerCommand($marshalled) };
  do { chomp($@); $sl->log("Unable to unmarshall command \"$marshalled\" ($@)",1); return [$marshalled] } unless(defined $r_cmd);
  $r_cmd->[0]='#'.$cmdId.' '.$r_cmd->[0] if(defined $cmdId);
  return $r_cmd;
}

# Helper ######################################################################

sub aindex (\@$;$) {
  my ($aref, $val, $pos) = @_;
  for ($pos ||= 0; $pos < @$aref; $pos++) {
    return $pos if $aref->[$pos] eq $val;
  }
  return -1;
}

# Business functions ##########################################################

sub storeRunningBattle {
  my $self=shift;
  $self->{runningBattle}=dclone($self->{battles}{$self->{battle}{battleId}});
  foreach my $k (keys %{$self->{battle}}) {
    if(ref($self->{battle}{$k})) {
      $self->{runningBattle}{$k}=dclone($self->{battle}{$k});
    }else{
      $self->{runningBattle}{$k}=$self->{battle}{$k};
    }
  }
  if(exists $self->{runningBattle}{users}) {
    foreach my $user (keys %{$self->{runningBattle}{users}}) {
      foreach my $k (keys %{$self->{users}{$user}}) {
        if(ref($self->{users}{$user}{$k})) {
          $self->{runningBattle}{users}{$user}{$k}=dclone($self->{users}{$user}{$k});
        }else{
          $self->{runningBattle}{users}{$user}{$k}=$self->{users}{$user}{$k};
        }
      }
    }
  }
}

sub getSkillValue {
  my $skillString=shift;
  return $1 if($skillString =~ /(\d+(?:\.\d+)?)/);
  return 0;
}

sub specSort {
  my ($p_bData,$a,$b)=@_;
  my ($skillA,$skillB,$skillSigmaA,$skillSigmaB)=(0,0,10,10);
  if(exists $p_bData->{scriptTags}{'game/players/'.lc($a).'/skill'}) {
    $skillA=getSkillValue($p_bData->{scriptTags}{'game/players/'.lc($a).'/skill'});
    if(exists $p_bData->{scriptTags}{'game/players/'.lc($a).'/skilluncertainty'}) {
      $skillSigmaA=$p_bData->{scriptTags}{'game/players/'.lc($a).'/skilluncertainty'};
    }
  }
  if(exists $p_bData->{scriptTags}{'game/players/'.lc($b).'/skill'}) {
    $skillB=getSkillValue($p_bData->{scriptTags}{'game/players/'.lc($b).'/skill'});
    if(exists $p_bData->{scriptTags}{'game/players/'.lc($b).'/skilluncertainty'}) {
      $skillSigmaB=$p_bData->{scriptTags}{'game/players/'.lc($b).'/skilluncertainty'};
    }
  }
  return $skillB <=> $skillA if($skillA != $skillB);
  return $skillSigmaA <=> $skillSigmaB;
}

# TODO: refactor this horrible function
sub generateStartData {
  my ($self,$p_additionalData,$p_sides,$p_battleData,$autoHostMode)=@_;
  $autoHostMode=1 unless(defined $autoHostMode);
  my $sl=$self->{conf}{simpleLog};
  $p_additionalData={} unless(defined $p_additionalData);
  if(! (defined $p_battleData)) {
    if(! %{$self->{runningBattle}}) {
      if(exists $self->{battle}{battleId}) {
        $self->storeRunningBattle();
      }else{
        $sl->log("Unable to generate start data (no battle data)",1);
        return (undef,undef,undef);
      }
    }
    $p_battleData=$self->getRunningBattle();
  }
  my %battleData=%{$p_battleData};
  if(! %battleData) {
    $sl->log("Unable to generate start data (no battle data)",1);
    return (undef,undef,undef);
  }
  
  my $myPlayerNum=0;

  my $nextTeam=0;
  my %teamsMap;
  my %teamsData;

  my $nextAllyTeam=0;
  my %allyTeamsMap;
  my %allyTeamsData;

  shift(@{$battleData{userList}}) if($autoHostMode == 1 && $battleData{userList}->[0] eq $self->{login});

  my (@playerList,@specList);
  foreach my $user (@{$battleData{userList}}) {
    if(defined $battleData{users}{$user}{battleStatus} && $battleData{users}{$user}{battleStatus}{mode}) {
      push(@playerList,$user);
    }else{
      push(@specList,$user);
    }
  }
  my @orderedPlayers = sort { $battleData{users}{$a}{battleStatus}{id} <=> $battleData{users}{$b}{battleStatus}{id} } @playerList;
  my @orderedSpecs = sort { specSort(\%battleData,$a,$b) } @specList;
  $battleData{userList}=[@orderedPlayers,@orderedSpecs];

  my @orderedBots = sort { $battleData{bots}{$a}{battleStatus}{id} <=> $battleData{bots}{$b}{battleStatus}{id} } @{$battleData{botList}};
  $battleData{botList}=\@orderedBots;

  for my $userIndex (0..$#{$battleData{userList}}) {
    my $user=$battleData{userList}->[$userIndex];
    $myPlayerNum=$userIndex if($user eq $self->{login});
    my $p_battleStatus=$battleData{users}{$user}{battleStatus};
    if(defined $p_battleStatus && $p_battleStatus->{mode}) {
      if($p_battleStatus->{side} > $#{$p_sides}) {
        $sl->log("Side number of player \"$user\" is too big ($p_battleStatus->{side}), using max value for current MOD instead ($#{$p_sides})",2);
        $p_battleStatus->{side}=$#{$p_sides};
      }
      if(! exists $teamsMap{$p_battleStatus->{id}}) {
        my $allyTeam;
        if(! exists $allyTeamsMap{$p_battleStatus->{team}}) {
          $allyTeam=$nextAllyTeam++;
          $allyTeamsMap{$p_battleStatus->{team}}=$allyTeam;
        }else{
          $allyTeam=$allyTeamsMap{$p_battleStatus->{team}};
        }
        my $p_color = $battleData{users}{$user}{color};
        my $red=sprintf("%.5f",($p_color->{red} / 255));
        my $blue=sprintf("%.5f",($p_color->{blue} / 255));
        my $green=sprintf("%.5f",($p_color->{green} / 255));
        $teamsData{$nextTeam}= { TeamLeader => $userIndex,
                                 AllyTeam => $allyTeam,
                                 RgbColor => "$red $green $blue",
                                 Side => $p_sides->[$p_battleStatus->{side}],
                                 Handicap => $p_battleStatus->{bonus} };
        $teamsMap{$p_battleStatus->{id}}=$nextTeam++;
      }
    }
  }

  for my $botIndex (0..$#{$battleData{botList}}) {
    my $bot=$battleData{botList}->[$botIndex];
    my $p_battleStatus=$battleData{bots}{$bot}{battleStatus};
    if($p_battleStatus->{side} > $#{$p_sides}) {
      $sl->log("Side number of bot \"$bot\" is too big ($p_battleStatus->{side}), using max value for current MOD instead ($#{$p_sides})",2);
      $p_battleStatus->{side}=$#{$p_sides};
    }
    if(! exists $teamsMap{$p_battleStatus->{id}}) {
      my $allyTeam;
      if(! exists $allyTeamsMap{$p_battleStatus->{team}}) {
        $allyTeam=$nextAllyTeam++;
        $allyTeamsMap{$p_battleStatus->{team}}=$allyTeam;
      }else{
        $allyTeam=$allyTeamsMap{$p_battleStatus->{team}};
      }
      my $p_color = $battleData{bots}{$bot}{color};
      my $red=sprintf("%.5f",($p_color->{red} / 255));
      my $blue=sprintf("%.5f",($p_color->{blue} / 255));
      my $green=sprintf("%.5f",($p_color->{green} / 255));
      $teamsData{$nextTeam}= { AllyTeam => $allyTeam,
                               RgbColor => "$red $green $blue",
                               Side => $p_sides->[$p_battleStatus->{side}],
                               Handicap => $p_battleStatus->{bonus} };
      $teamsMap{$p_battleStatus->{id}}=$nextTeam++;
    }
    my $team=$teamsMap{$p_battleStatus->{id}};
    $teamsData{$team}{TeamLeader}=aindex(@{$battleData{userList}},$battleData{bots}{$bot}{owner});
  }
  
  foreach my $allyTeam (keys %allyTeamsMap) {
    my $realAllyTeam = $allyTeamsMap{$allyTeam};
    if(exists $battleData{startRects}{$allyTeam}) {
      $allyTeamsData{$realAllyTeam}= { StartRectTop => $battleData{startRects}{$allyTeam}{top}/200,
                                       StartRectLeft => $battleData{startRects}{$allyTeam}{left}/200,
                                       StartRectBottom => $battleData{startRects}{$allyTeam}{bottom}/200,
                                       StartRectRight => $battleData{startRects}{$allyTeam}{right}/200 };
    }else{
      $allyTeamsData{$realAllyTeam}= {};
    }
  }

  foreach my $allyTeam (sort keys %{$battleData{startRects}}) {
    next if(exists $allyTeamsMap{$allyTeam});
    $allyTeamsData{$nextAllyTeam++}= { StartRectTop => $battleData{startRects}{$allyTeam}{top}/200,
                                       StartRectLeft => $battleData{startRects}{$allyTeam}{left}/200,
                                       StartRectBottom => $battleData{startRects}{$allyTeam}{bottom}/200,
                                       StartRectRight => $battleData{startRects}{$allyTeam}{right}/200 };
  }

  my @startData=("[GAME]","{");
  push(@startData,"  Mapname=$battleData{map};");
  push(@startData,"  Gametype=$battleData{mod};");
  push(@startData,"");
  foreach my $tag (keys %{$battleData{scriptTags}}) {
    my $realTag=$tag;
    if($tag =~ /^game\/([^\/]*)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"  $realTag=$battleData{scriptTags}{$tag};");
  }
  push(@startData,"");
  foreach my $tag (keys %{$p_additionalData}) {
    my $realTag=$tag;
    if($tag =~ /^game\/([^\/]+)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"  $realTag=$p_additionalData->{$tag};");
  }
  push(@startData,"");
  push(@startData,"  HostIP=$battleData{ip};") if($battleData{founder} ne $self->{login});
  push(@startData,"  HostPort=$battleData{port};");
  push(@startData,"");
  if($autoHostMode) {
    push(@startData,"  AutoHostName=$self->{login};");
    push(@startData,"  AutoHostCountryCode=$self->{users}{$self->{login}}{country};");
    push(@startData,"  AutoHostRank=$self->{users}{$self->{login}}{status}{rank};");
    push(@startData,"  AutoHostAccountId=$self->{users}{$self->{login}}{accountId};");
    push(@startData,"");
  }
  if($autoHostMode != 1) {
    push(@startData,"  MyPlayerName=$self->{login};");
    push(@startData,"  MyPlayerNum=$myPlayerNum;");
  }
  if($battleData{founder} eq $self->{login}) {
    push(@startData,"  IsHost=1;");
  }else{
    push(@startData,"  IsHost=0;");
  }
  push(@startData,"");
  push(@startData,"  NumPlayers=".($#{$battleData{userList}}+1).";");
  push(@startData,"  NumTeams=$nextTeam;");
  push(@startData,"  NumAllyTeams=$nextAllyTeam;");
  push(@startData,"");

  for my $userIndex (0..$#{$battleData{userList}}) {
    my $user=$battleData{userList}->[$userIndex];
    my $p_battleStatus=$battleData{users}{$user}{battleStatus}//{mode => 0};
    push(@startData,"  [PLAYER$userIndex]");
    push(@startData,"  {");
    push(@startData,"    Name=$user;");
    push(@startData,"    Password=$battleData{users}{$user}{scriptPass};") if(defined $battleData{users}{$user}{scriptPass});
    push(@startData,"    Spectator=".(1 - $p_battleStatus->{mode}).";");
    push(@startData,"    Team=$teamsMap{$p_battleStatus->{id}};") if($p_battleStatus->{mode});
    if(exists $self->{users}{$user}) {
      my $playerAccountId=$self->{users}{$user}{accountId};
      push(@startData,"    CountryCode=$self->{users}{$user}{country};");
      push(@startData,"    Rank=$self->{users}{$user}{status}{rank};");
      push(@startData,"    AccountId=$playerAccountId;");
      if(exists $p_additionalData->{playerData} && exists $p_additionalData->{playerData}{$playerAccountId}) {
        foreach my $tag (keys %{$p_additionalData->{playerData}{$playerAccountId}}) {
          if(ref $p_additionalData->{playerData}{$playerAccountId}{$tag} eq 'HASH') {
            push(@startData,"    [$tag]");
            push(@startData,"    {");
            foreach my $subTag (keys %{$p_additionalData->{playerData}{$playerAccountId}{$tag}}) {
              push(@startData,"      $subTag=$p_additionalData->{playerData}{$playerAccountId}{$tag}{$subTag};")
            }
            push(@startData,"    }");
          }else{
            push(@startData,"    $tag=$p_additionalData->{playerData}{$playerAccountId}{$tag};")
          }
        }
      }
    }
    push(@startData,'    Skill='.$battleData{scriptTags}{'game/players/'.lc($user).'/skill'}.';') if(exists $battleData{scriptTags}{'game/players/'.lc($user).'/skill'});
    push(@startData,'    SkillUncertainty='.$battleData{scriptTags}{'game/players/'.lc($user).'/skilluncertainty'}.';') if(exists $battleData{scriptTags}{'game/players/'.lc($user).'/skilluncertainty'});
    push(@startData,"  }");
  }
  for my $botIndex (0..$#{$battleData{botList}}) {
    my $bot=$battleData{botList}->[$botIndex];
    my $p_battleStatus=$battleData{bots}{$bot}{battleStatus};
    my $team=$teamsMap{$p_battleStatus->{id}};
    my $aiShortName=$battleData{bots}{$bot}{aiDll};
    my $aiVersion;
    ($aiShortName,$aiVersion)=($1,$2) if($aiShortName =~ /^([^\|]+)\|(.+)$/);
    push(@startData,"  [AI$botIndex]");
    push(@startData,"  {");
    push(@startData,"    Name=$bot;");
    push(@startData,"    ShortName=$aiShortName;");
    push(@startData,"    Team=$team;");
    push(@startData,"    Host=".aindex(@{$battleData{userList}},$battleData{bots}{$bot}{owner}).';');
    push(@startData,"    Version=$aiVersion;") if(defined $aiVersion);
    if(exists $p_additionalData->{aiData} && exists $p_additionalData->{aiData}{$bot}) {
      foreach my $tag (keys %{$p_additionalData->{aiData}{$bot}}) {
        if(ref $p_additionalData->{aiData}{$bot}{$tag} eq 'HASH') {
          push(@startData,"    [$tag]");
          push(@startData,"    {");
          foreach my $subTag (keys %{$p_additionalData->{aiData}{$bot}{$tag}}) {
            push(@startData,"      $subTag=$p_additionalData->{aiData}{$bot}{$tag}{$subTag};")
          }
          push(@startData,"    }");
        }else{
          push(@startData,"    $tag=$p_additionalData->{aiData}{$bot}{$tag};")
        }
      }
    }
    push(@startData,"  }");
  }

  push(@startData,"");

  for my $teamIndex (sort (keys %teamsData)) {
    push(@startData,"  [TEAM$teamIndex]");
    push(@startData,"  {");
    foreach my $k (keys %{$teamsData{$teamIndex}}) {
      push(@startData,"    $k=$teamsData{$teamIndex}{$k};");
    }
    push(@startData,"  }"); 
  }

  push(@startData,"");

  for my $teamAllyIndex (sort (keys %allyTeamsData)) {
    push(@startData,"  [ALLYTEAM$teamAllyIndex]");
    push(@startData,"  {");
    push(@startData,"    NumAllies=0;");
    foreach my $k (keys %{$allyTeamsData{$teamAllyIndex}}) {
      push(@startData,"    $k=$allyTeamsData{$teamAllyIndex}{$k};");
    }
    push(@startData,"  }"); 
  }

  push(@startData,"");

  push(@startData,"  NumRestrictions=".(scalar keys %{$battleData{restrictedUnits}}).";");
  push(@startData,"  [RESTRICT]");
  push(@startData,"  {");
  my $uIndex=0;
  foreach my $restrictedUnit (keys %{$battleData{restrictedUnits}}) {
    push(@startData,"    Unit$uIndex=$restrictedUnit;");
    push(@startData,"    Limit$uIndex=$battleData{restrictedUnits}{$restrictedUnit};");
    $uIndex++;
  }
  push(@startData,"  }");

  push(@startData,"  [MODOPTIONS]");
  push(@startData,"  {");
  foreach my $tag (keys %{$battleData{scriptTags}}) {
    my $realTag=$tag;
    if($tag =~ /^game\/modoptions\/(.+)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"    $realTag=$battleData{scriptTags}{$tag};");
  }
  foreach my $tag (keys %{$p_additionalData}) {
    my $realTag=$tag;
    if($tag =~ /^game\/modoptions\/(.+)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"    $realTag=$p_additionalData->{$tag};");
  }
  push(@startData,"  }");

  push(@startData,"  [MAPOPTIONS]");
  push(@startData,"  {");
  foreach my $tag (keys %{$battleData{scriptTags}}) {
    my $realTag=$tag;
    if($tag =~ /^game\/mapoptions\/(.+)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"    $realTag=$battleData{scriptTags}{$tag};");
  }
  foreach my $tag (keys %{$p_additionalData}) {
    my $realTag=$tag;
    if($tag =~ /^game\/mapoptions\/(.+)$/i) {
      $realTag=$1;
    }else{
      next;
    }
    push(@startData,"    $realTag=$p_additionalData->{$tag};");
  }
  push(@startData,"  }");

  foreach my $tag (sort keys %{$p_additionalData}) {
    next if(any {$tag eq $_} (qw'playerData aiData'));
    if(ref $p_additionalData->{$tag} eq 'HASH') {
      push(@startData,"  [$tag]");
      push(@startData,"  {");
      foreach my $subTag (sort keys %{$p_additionalData->{$tag}}) {
        push(@startData,"    $subTag=$p_additionalData->{$tag}{$subTag};")
      }
      push(@startData,"  }");
    }
  }
  push(@startData,"}");

  return (\@startData,\%teamsMap,\%allyTeamsMap);
}

sub addCallbacks {
  my ($self,$p_callbacks,$nbCalls,$priority)=@_;
  $priority=caller() unless(defined $priority);
  $nbCalls=0 unless(defined $nbCalls);
  my %callbacks=%{$p_callbacks};
  foreach my $command (keys %callbacks) {
    $self->{callbacks}{$command}={} unless(exists $self->{callbacks}{$command});
    if(exists $self->{callbacks}{$command}{$priority}) {
      $self->{conf}{simpleLog}->log("Replacing an existing $command callback for priority \"$priority\"",2);
    }
    $self->{callbacks}{$command}{$priority}=[$callbacks{$command},$nbCalls];
  }
}

sub removeCallbacks {
  my ($self,$p_commands,$priority)=@_;
  $priority=caller() unless(defined $priority);
  my @commands=@{$p_commands};
  foreach my $command (@commands) {
    if(exists $self->{callbacks}{$command}) {
      delete $self->{callbacks}{$command}{$priority};
      delete $self->{callbacks}{$command} unless(%{$self->{callbacks}{$command}});
    }
  }
}

sub addPreCallbacks {
  my ($self,$p_preCallbacks,$priority)=@_;
  $priority=caller() unless(defined $priority);
  foreach my $command (keys %{$p_preCallbacks}) {
    $self->{preCallbacks}{$command}={} unless(exists $self->{preCallbacks}{$command});
    if(exists $self->{preCallbacks}{$command}{$priority}) {
      $self->{conf}{simpleLog}->log("Replacing an existing $command pre-callback for priority \"$priority\"",2);
    }
    $self->{preCallbacks}{$command}{$priority}=$p_preCallbacks->{$command};
  }
}

sub removePreCallbacks {
  my ($self,$p_commands,$priority)=@_;
  $priority=caller() unless(defined $priority);
  foreach my $command (@{$p_commands}) {
    if(exists $self->{preCallbacks}{$command}) {
      delete $self->{preCallbacks}{$command}{$priority};
      delete $self->{preCallbacks}{$command} unless(%{$self->{preCallbacks}{$command}});
    }
  }
}

sub checkTimeouts {
  my $self = shift;
  my $sl=$self->{conf}{simpleLog};
  foreach my $pr (keys %{$self->{pendingRequests}}) {
    my ($p_callbacks,$timeout,$p_timeoutCallback)=@{$self->{pendingRequests}{$pr}};
    if(time > $timeout) {
      $sl->log("Timeout for request \"$pr\"",2);
      foreach my $cbtr (keys %{$p_callbacks}) {
        delete $self->{pendingResponses}{$cbtr};
      }
      delete $self->{pendingRequests}{$pr};
      if($p_timeoutCallback) {
        &{$p_timeoutCallback}($pr);
      }
    }
  }
}

sub connect {
  my ($self,$disconnectCallback,$p_callbacks,$timeoutCallback) = @_;
  my $priority=caller();
  my %conf=%{$self->{conf}};
  my $sl=$conf{simpleLog};
  $sl->log("Connecting to $conf{serverHost}:$conf{serverPort}",3);
  if((defined $self->{lobbySock}) && $self->{lobbySock}) {
    $sl->log("Could not connect to lobby server, already connected!",2);
    return $self->{lobbySock};
  }
  $self->{lobbySock} = new IO::Socket::INET(PeerHost => $conf{serverHost},
                                            PeerPort => $conf{serverPort},
                                            Proto => 'tcp',
                                            Blocking => 1,
                                            Timeout => $conf{timeout});
  if(! $self->{lobbySock}) {
    $sl->log("Unable to connect to lobby server $conf{serverHost}:$conf{serverPort} ($@)",0);
    undef $self->{lobbySock};
    return 0;
  }
  $self->{lastSndTs}=time;
  if(defined $disconnectCallback) {
    $self->{callbacks}{"_DISCONNECT_"}={} unless(exists $self->{callbacks}{"_DISCONNECT_"});
    $self->{callbacks}{"_DISCONNECT_"}{$priority}=$disconnectCallback;
  }
  if(defined $p_callbacks) {
    my %callbacks=%{$p_callbacks};
    if(%callbacks) {
      if(! defined $timeoutCallback) {
        $timeoutCallback=0;
      }
      foreach my $response (keys %callbacks) {
        $self->{pendingResponses}{$response}='_CONNECT_';
      }
      $self->{pendingRequests}{'_CONNECT_'}=[$p_callbacks,time+$conf{timeout},$timeoutCallback];
    }
  }
  return $self->{lobbySock};
}

sub gracefulSocketShutdown {
  my $socket=shift;
  local $SIG{PIPE} = 'IGNORE';
  shutdown($socket,1);
  my $timeoutTime=time+5;
  my $nbLingerPackets=0;
  my $shutdownSel=IO::Select->new($socket);
  while($nbLingerPackets<10) {
    my $maxWait=$timeoutTime-time;
    $maxWait=0 if($maxWait < 0);
    last unless($shutdownSel->can_read($maxWait));
    my $readLength=$socket->sysread(my $ignored,4096);
    last unless($readLength);
    $nbLingerPackets++ unless($maxWait);
  }
  close($socket);
}

sub disconnect {
  my $self = shift;
  my %conf=%{$self->{conf}};
  my $sl=$conf{simpleLog};
  $sl->log("Disconnecting from $conf{serverHost}:$conf{serverPort}",3);
  if(! ((defined $self->{lobbySock}) && $self->{lobbySock})) {
    $sl->log("Unable to disconnect from lobby server, already disconnected!",2);
  }else{
    gracefulSocketShutdown($self->{lobbySock}) if($self->{lobbySock}->connected());
    undef $self->{lobbySock};
  }
  $self->{login}=undef;
  $self->{compatFlags}={};
  $self->{protocolExtensions}={};
  $self->{serverParams}={};
  $self->{users}={};
  $self->{accounts}={};
  $self->{channels}={};
  $self->{battles}={};
  $self->{battle}={};
  $self->{runningBattle}={};
  $self->{callbacks}={};
  $self->{preCallbacks}={};
  $self->{pendingRequests}={};
  $self->{pendingResponses}={};
  $self->{openBattleModHash}=0;
  $self->{password}='*';
  $self->{lastSndTs}=0;
  $self->{lastRcvTs}=0;
  $self->{tlsCertifHash}=undef;
  $self->{tlsServerIsAuthenticated}=undef;
  $self->{performingTlsHandshake}=undef;
  delete $self->{startTlsCallback};
}

sub sendCommand {
  my ($self,$p_command,$p_callbacks,$p_timeoutCallback) = @_;
  my $r_conf=$self->{conf};
  my $sl=$r_conf->{simpleLog};
  if(! ((defined $self->{lobbySock}) && $self->{lobbySock})) {
    $sl->log("Unable to send command, not connected to lobby server",1);
    return 0;
  }
  my $commandName=$p_command->[0];
  if($commandName =~ /^\#\d+\s+([^\s]+)$/) {
    $commandName=$1;
  }
  if(exists $commandHooks{$commandName}) {
    my $hook=$commandHooks{$commandName};
    &{$hook}($self,@{$p_command});
  }
  my $lobbySock=$self->{lobbySock};
  my $command=$self->marshallCommand($p_command);
  return 0 unless(defined $command);
  my $cmdText=$command;
  chomp($cmdText);
  $sl->log("Sending to lobby server: \"$cmdText\"",5);
  my $printRc;
  {
    local $SIG{PIPE} = 'IGNORE';
    $printRc=print $lobbySock $command;
  }
  if(! defined $printRc) {
    $sl->log("Failed to send following command to lobby server \"$cmdText\" ($!)",1);
    return 0;
  }
  $self->{lastSndTs}=time;
  if(defined $p_callbacks) {
    my %callbacks=%{$p_callbacks};
    if(%callbacks) {
      if(! defined $p_timeoutCallback) {
        $p_timeoutCallback=0;
      }
      foreach my $response (keys %callbacks) {
        $self->{pendingResponses}{$response}=$p_command->[0];
      }
      $self->{pendingRequests}{$p_command->[0]}=[$p_callbacks,time+$r_conf->{timeout},$p_timeoutCallback];
    }
  }
  return 1;
}

sub prioSort {
  if($a =~ /^\d+$/ && $b =~ /^\d+$/) {
    return $a <=> $b;
  }
  if($a =~ /^\d+$/) {
    return $a <=> 1000;
  }
  if($b =~ /^\d+$/) {
    return 1000 <=> $b;
  }
  return 0;
}

sub receiveCommand {
  my $self=shift;
  my $r_conf=$self->{conf};
  my $sl=$r_conf->{simpleLog};
  if(! ((defined $self->{lobbySock}) && $self->{lobbySock})) {
    $sl->log("Unable to receive command from lobby server, not connected!",1);
    return 0;
  }
  return $self->doTlsHandshake() if($self->{performingTlsHandshake});
  my $lobbySock=$self->{lobbySock};
  my ($readLength,$data);
  {
    local $SIG{PIPE} = 'IGNORE';
    $readLength=$lobbySock->sysread($data,4096);
  }
  my $readError;
  if(defined $readLength) {
    if($readLength) {
      $readError='Unknown error while reading data from socket' unless(defined $data && $data ne '');
    }else{
      $readError='Connection closed by peer';
    }
  }else{
    $readError=$lobbySock->errstr() if($lobbySock->can('errstr'));
    $readError=$! unless(defined $readError && $readError ne '');
    $readError='Error while reading data from socket: '.$readError;
  }
  if(defined $readError) {
    $sl->log($readError,2);
    if(exists($self->{preCallbacks}{'_DISCONNECT_'})) {
      foreach my $prio (sort prioSort (keys %{$self->{preCallbacks}{'_DISCONNECT_'}})) {
        my $p_preCallback=$self->{preCallbacks}{'_DISCONNECT_'}{$prio};
        &{$p_preCallback}() if($p_preCallback);
      }
    }
    if(exists $self->{callbacks}{"_DISCONNECT_"}) {
      foreach my $prio (sort prioSort (keys %{$self->{callbacks}{'_DISCONNECT_'}})) {
        &{$self->{callbacks}{'_DISCONNECT_'}{$prio}}();
      }
    }
    return 0;
  }
  my @commands=split(/(?<=\cJ)/, $data);
  my $rc=1;
  for my $commandNb (0..$#commands) {
    my $marshalledCommand=$commands[$commandNb];
    if($commandNb == 0) {
      $marshalledCommand=$self->{readBuffer}.$marshalledCommand;
      $self->{readBuffer}="";
    }
    if($commandNb == $#commands && $marshalledCommand !~ /\cJ$/) {
      $self->{readBuffer}=$marshalledCommand;
      last;
    }
    chomp($marshalledCommand);
    if($marshalledCommand eq '') {
      $sl->log("Ignoring empty command received from lobby server",5);
      next;
    }
    $self->{lastRcvTs}=time;
    my $p_command=$self->unmarshallCommand($marshalledCommand);
    $sl->log("Received from lobby server: \"$marshalledCommand\", unmarshalled as:\"".join(",",@{$p_command})."\"",5);
    my $commandName=$p_command->[0];
    my $realCommandName=$commandName;
    if($commandName =~ /^\#\d+\s+([^\s]+)$/) {
      $realCommandName=$1;
    }
    my $processed=0;
    
    if(exists($self->{preCallbacks}{'_ALL_'})) {
      foreach my $prio (sort prioSort (keys %{$self->{preCallbacks}{'_ALL_'}})) {
        $processed=1;
        my $p_preCallback=$self->{preCallbacks}{'_ALL_'}{$prio};
        &{$p_preCallback}(@{$p_command}) if($p_preCallback);
      }
    }
    if(exists($self->{preCallbacks}{$realCommandName})) {
      foreach my $prio (sort prioSort (keys %{$self->{preCallbacks}{$realCommandName}})) {
        $processed=1;
        my $p_preCallback=$self->{preCallbacks}{$realCommandName}{$prio};
        &{$p_preCallback}(@{$p_command}) if($p_preCallback);
      }
    }

    my ($handlerTime,$callbackTime);
    if(exists($commandHandlers{$realCommandName})) {
      $processed=1;
      $handlerTime=time;
      if($commandHandlers{$realCommandName}) {
        my $handlerRc=&{$commandHandlers{$realCommandName}}($self,@{$p_command});
        $rc = $handlerRc && $rc;
        &{$r_conf->{inconsistencyHandler}}($realCommandName,$marshalledCommand) if(! $handlerRc && $r_conf->{inconsistencyHandler});
      }
      $handlerTime=time-$handlerTime;
    }
    my $cName="_DEFAULT_";
    if(exists($self->{callbacks}{$realCommandName})) {
      $cName=$realCommandName;
    }
    if(exists($self->{callbacks}{$commandName})) {
      $cName=$commandName;
    }
    if(exists($self->{callbacks}{$cName})) {
      foreach my $prio (sort prioSort (keys %{$self->{callbacks}{$cName}})) {
        my ($callback,$nbCalls)=@{$self->{callbacks}{$cName}{$prio}};
        $processed=1;
        if($nbCalls == 1) {
          delete $self->{callbacks}{$cName}{$prio};
        }elsif($nbCalls > 1) {
          $nbCalls-=1;
          $self->{callbacks}{$cName}{$prio}=[$callback,$nbCalls];
        }
        $callbackTime=time;
        $rc = &{$callback}(@{$p_command}) && $rc if($callback);
        $callbackTime=time-$callbackTime;
      }
      delete $self->{callbacks}{$cName} unless(%{$self->{callbacks}{$cName}});
    }
    if(defined $handlerTime) {
      if(defined $callbackTime) {
        if($handlerTime || $callbackTime) {
          my $statsLevel=5;
          my $maxTime=$handlerTime;
          $maxTime=$callbackTime if($callbackTime > $handlerTime);
          $statsLevel=4 if($maxTime > 1);
          $sl->log("Stats for $realCommandName: internal handler took $handlerTime second(s) and callback took $callbackTime second(s)",$statsLevel);
        }
      }elsif($handlerTime) {
        my $statsLevel=5;
        $statsLevel=4 if($handlerTime > 1);
        $sl->log("Stats for $realCommandName: internal handler took $handlerTime second(s)",$statsLevel);
      }
    }elsif(defined $callbackTime && $callbackTime) {
      my $statsLevel=5;
      $statsLevel=4 if($callbackTime > 1);
      $sl->log("Stats for $realCommandName: callback took $callbackTime second(s)",$statsLevel);
    }
    $cName=$realCommandName;
    if(exists($self->{pendingResponses}{$commandName})) {
      $cName=$commandName;
    }
    if(exists($self->{pendingResponses}{$cName})) {
      my $request=$self->{pendingResponses}{$cName};
      my ($p_callbacks,$timeout,$p_timeoutCallback)=@{$self->{pendingRequests}{$request}};
      my $callback=$p_callbacks->{$cName};
      foreach my $cbtr (keys %{$p_callbacks}) {
        delete $self->{pendingResponses}{$cbtr};
      }
      delete $self->{pendingRequests}{$request};
      $processed=1;
      $rc = &{$callback}(@{$p_command}) && $rc if($callback);
    }
    if(! $processed && $r_conf->{warnForUnhandledMessages}) {
      $sl->log("Unexpected/unhandled command received: \"$marshalledCommand\"",2);
      $rc=0;
    }
  }
  return $rc;
};

# Internal handlers and hooks #################################################

sub checkIntParams {
  my ($self,$commandName,$p_paramNames,$p_paramPointers)=@_;
  my $sl=$self->{conf}{simpleLog};
  if($#{$p_paramNames} != $#{$p_paramPointers}) {
    $sl->log("Invalid call of checkIntParams: paramNames length is $#{$p_paramNames} whereas paramPointers length is $#{$p_paramPointers}",1);
    return {};
  }
  my %invalidParams;
  for my $i (0..$#{$p_paramNames}) {
    if(! defined ${$p_paramPointers->[$i]}) {
      $invalidParams{$p_paramNames->[$i]}=${$p_paramPointers->[$i]};
      $sl->log("Found undefined $p_paramNames->[$i] parameter value (should be integer) in lobby command $commandName",2);
      ${$p_paramPointers->[$i]}=0;
    }
    if(${$p_paramPointers->[$i]} !~ /^-?\d+$/) {
      $invalidParams{$p_paramNames->[$i]}=${$p_paramPointers->[$i]};
      $sl->log("Found invalid $p_paramNames->[$i] parameter value \"${$p_paramPointers->[$i]}\" (should be integer) in lobby command $commandName",2);
      ${$p_paramPointers->[$i]}=0;
    }
  }
  return \%invalidParams;
}

sub tasserverHandler {
  my ($self,undef,$protocolVersion,$defaultSpringVersion,$natHelperUdpPort,$serverMode)=@_;
  my $sl=$self->{conf}{simpleLog};
  my $r_checkParamsRes=$self->checkIntParams('TASSERVER',['natHelperUdpPort','serverMode'],[\$natHelperUdpPort,\$serverMode]);
  $self->{serverParams}={protocolVersion => $protocolVersion,
                         defaultSpringVersion => $defaultSpringVersion,
                         natHelperUdpPort => $natHelperUdpPort,
                         serverMode => $serverMode};
  if($protocolVersion =~ /^(\d+\.\d+)/) {
    if($1 > 0.36) {
      $self->{compatFlags}{l}=1;
      $self->{compatFlags}{t}=1;
    }
  }elsif($protocolVersion eq 'unknown') {
    $sl->log('The lobby server does NOT indicate the protocol version in use (compatibility with optional protocol extensions cannot be determined)',2);
  }else{
    $sl->log("Unknown format for lobby server protocol version: \"$protocolVersion\"",1);
    return 0;
  }
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub serverMsgHandler {
  my ($self,undef,$msg)=@_;
  return 1 unless(substr($msg,0,PROTOCOL_EXTENSIONS_PREFIX_LENGTH) eq PROTOCOL_EXTENSIONS_PREFIX);
  my $sl=$self->{conf}{simpleLog};
  my $r_protExt;
  eval { $r_protExt=JSON::PP::decode_json(substr($msg,PROTOCOL_EXTENSIONS_PREFIX_LENGTH)) };
  if($@) {
    $sl->log('Invalid JSON data in protocol extensions declaration received from lobby server',2);
    return 0;
  }elsif(ref $r_protExt ne 'HASH') {
    $sl->log('Invalid data in protocol extensions declaration received from lobby server',2);
    return 0;
  }
  map {$self->{protocolExtensions}{$_}=$r_protExt->{$_}} (keys %{$r_protExt});
  return 1;
}

sub startTls {
  my ($self,$r_callback)=@_;
  my $sl=$self->{conf}{simpleLog};
  $tlsAvailable //= eval {require IO::Socket::SSL; 1} ? 1 : 0;
  if(! $tlsAvailable) {
    $sl->log('Unable to start TLS: no TLS module available!',1);
    return 0;
  }
  if(exists $self->{startTlsCallback}) {
    $sl->log('Unable to start TLS: a TLS handshake is already in progress!',1);
    return 0;
  }
  if(defined $self->{tlsCertifHash}) {
    $sl->log('Unable to start TLS: TLS is already enabled!',1);
    return 0;
  }
  $self->sendCommand(['STLS'])
      or return 0;
  $self->{startTlsCallback}=$r_callback;
  return 1;
}

sub okHandler {
  my ($self,undef,$cmdParam)=@_;
  return 1 if(defined $cmdParam && $cmdParam ne '' && lc($cmdParam) ne 'cmd=stls');
  my $sl=$self->{conf}{simpleLog};
  $tlsAvailable //= eval {require IO::Socket::SSL; 1} ? 1 : 0;
  if(! $tlsAvailable) {
    $sl->log('Trying to activate TLS but no TLS module is available!',1);
    return 0;
  }
  if(defined $self->{tlsCertifHash}) {
    $sl->log('Duplicate OK command received from server, TLS is already enabled!',1);
    return 0;
  }
  $sl->log('Upgrading socket to IO::Socket::SSL...',5);
  if(IO::Socket::SSL->start_SSL($self->{lobbySock},
                                SSL_verify_callback => sub {$self->{tlsCertifIsInvalid}=1 unless($_[0]); return 1;},
                                SSL_verifycn_scheme => 'none',
                                SSL_startHandshake => 0)) {
      $sl->log('Starting TLS handshake...',5);
      $self->{performingTlsHandshake}=1;
      $self->{lobbySock}->blocking(0);
      return $self->doTlsHandshake();
  }else{
    $sl->log("Failed to upgrade socket: $IO::Socket::SSL::SSL_ERROR",1);
    my $r_callback = delete $self->{startTlsCallback};
    $r_callback->(0) if(defined $r_callback);
    return 0;
  }
}

sub doTlsHandshake {
  my $self=shift;
  my $r_conf=$self->{conf};
  my $sl=$r_conf->{simpleLog};
  if($self->{lobbySock}->connect_SSL()) {
    undef $self->{performingTlsHandshake};
    my $lobbySock=$self->{lobbySock};
    $lobbySock->blocking(1);
    $self->{tlsServerIsAuthenticated} = delete $self->{tlsCertifIsInvalid} ? 0 : $lobbySock->verify_hostname($r_conf->{serverHost});
    my $tlsCertifHash=$lobbySock->get_fingerprint('sha256');
    if($tlsCertifHash =~ /^sha256\$([\da-fA-F]+)$/) {
      $self->{tlsCertifHash}=lc($1);
      $sl->log('TLS enabled ('.($lobbySock->get_sslversion()).','.($lobbySock->get_cipher()).')',3);
      $sl->log("TLS server certificate fingerpint (SHA-256): $self->{tlsCertifHash}",5);
    }else{
      $sl->log("Invalid TLS server certificate fingerprint: \"$tlsCertifHash\"",1);
    }
    my $r_callback = delete $self->{startTlsCallback};
    $r_callback->(1) if(defined $r_callback);
    return 1;
  }elsif($! == Errno::EWOULDBLOCK) {
    $sl->log('TLS handshake in progress...',5);
    return 1;
  }else{
    $sl->log("Error during TLS handshake: $IO::Socket::SSL::SSL_ERROR",1);
    undef $self->{performingTlsHandshake};
    $self->{lobbySock}->blocking(1);
    my $r_callback = delete $self->{startTlsCallback};
    $r_callback->(0) if(defined $r_callback);
    return 0;
  }
}

sub loginHook {
  my ($self,$flagString)=($_[0],$_[8]);
  if(defined $flagString) {
    my @flags=split(' ',$flagString);
    @{$self->{compatFlags}}{@flags}=(1) x @flags;
  }
}

sub acceptedHandler {
  my ($self,undef,$login)=@_;
  $self->{login}=$login;
  return 1;
}

sub addUserHandler {
  my ($self,undef,$user,$country,$param3,$param4)=@_;
  my ($accountId,$lobbyClient);
  if(exists $self->{compatFlags}{l}) {
    ($accountId,$lobbyClient)=($param3,$param4);
  }else{
    $accountId=$param4;
  }
  $accountId=0 unless(defined $accountId && $accountId ne 'None');
  $lobbyClient//='';
  my $r_checkParamsRes=$self->checkIntParams('ADDUSER',['accountId'],[\$accountId]);
  my $sl=$self->{conf}{simpleLog};
  if(exists $self->{users}{$user}) {
    $sl->log("Ignoring duplicate ADDUSER command for user \"$user\"",2);
    return 0;
  }
  $self->{users}{$user} = { country => $country,
                            accountId => $accountId,
                            lobbyClient => $lobbyClient,
                            ip => undef,
                            status => { inGame => 0,
                                        rank => 0,
                                        away => 0,
                                        access => 0,
                                        bot => 0 },
                            channels => {},
                            battleId => undef };
  $self->{accounts}{$accountId}=$user if($accountId);
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub removeUserHandler {
  my ($self,undef,$user)=@_;
  my $sl=$self->{conf}{simpleLog};
  my $r_lobbyUserData=$self->{users}{$user};
  if(! defined $r_lobbyUserData) {
    $sl->log("Ignoring REMOVEUSER command (unknown user:\"$user\")",1);
    return 0;
  }
  my $rc=1;
  my $battleId=$r_lobbyUserData->{battleId};
  if(defined $battleId) {
    my $r_battleData=$self->{battles}{$battleId};
    my @userList=@{$r_battleData->{userList}};
    if($r_battleData->{founder} eq $user) {
      $sl->log("Missing BATTLECLOSED command before REMOVEUSER (user \"$user\")",2);
      map {$self->{users}{$_}{battleId}=undef} @userList;
      delete $self->{battles}{$battleId};
      $self->{battle}={} if(exists $self->{battle}{battleId} && $self->{battle}{battleId} == $battleId);
    }else{
      $sl->log("Missing LEFTBATTLE command before REMOVEUSER (user \"$user\")",2);
      my $userIndex=aindex(@userList,$user);
      splice(@userList,$userIndex,1);
      $self->{battles}{$battleId}{userList}=\@userList;
      if(exists $self->{battle}{battleId} && $self->{battle}{battleId} == $battleId) {
        my $r_orphanBots=$self->{battle}{users}{$user}{bots};
        if(%{$r_orphanBots}) {
          my @newBotList;
          map {push(@newBotList,$_) unless(exists $r_orphanBots->{$_})} @{$self->{battle}{botList}};
          $self->{battle}{botList}=\@newBotList;
          map {delete $self->{battle}{bots}{$_}} (keys %{$r_orphanBots});
        }
        delete $self->{battle}{users}{$user};
      }
    }
    $rc=0;
  }
  my @userChannels = keys %{$self->{users}{$user}{channels}};
  if(@userChannels) {
    $sl->log("Missing LEFT command before REMOVEUSER (user \"$user\", channel".(@userChannels>1?'s':'').': '.join(', ',@userChannels).')',2);
    map {delete $self->{channels}{$_}{users}{$user}} @userChannels;
  }
  delete $self->{accounts}{$self->{users}{$user}{accountId}} if($self->{users}{$user}{accountId});
  delete $self->{users}{$user};
  return $rc;
}

sub clientStatusHandler {
  my ($self,undef,$user,$status)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{users}{$user}) {
    $sl->log("Ignoring CLIENTSTATUS command (unknown user:\"$user\")",1);
    return 0;
  }
  my $p_clientStatus = $self->unmarshallClientStatus($status);
  if($user eq $self->{login}) {
    my $currentInGameStatus=$self->{users}{$user}{status}{inGame};
    if( $currentInGameStatus == 0 && $p_clientStatus->{inGame} == 1) {
      if(exists $self->{battle}{battleId}) {
        $self->storeRunningBattle();
      }
    }elsif($currentInGameStatus == 1 && $p_clientStatus->{inGame} == 0) {
      $self->{runningBattle}={};
    }
  }
  $self->{users}{$user}{status}=$p_clientStatus;
  return 1;
}

sub channelTopicHandler {
  my ($self,undef,$chan,$user,$topic)=@_;
  $topic=$_[5] unless(exists $self->{compatFlags}{t});
  $topic//='';
  if(! exists $self->{channels}{$chan}) {
    $self->{conf}{simpleLog}->log("Ignoring CHANNELTOPIC command (non joined channel:\"$chan\")",1);
    return 0;
  }
  $self->{channels}{$chan}{topic}={author => $user,
                                   content => $topic};
  return 1;
}

sub joinHandler {
  my ($self,undef,$channel)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(exists $self->{channels}{$channel}) {
    $sl->log("Ignoring JOIN command (already joined channel:\"$channel\")",1);
    return 0;
  }
  my $login=$self->{login};
  $self->{channels}{$channel}={topic => {}, users => {$login => 1}};
  $self->{users}{$login}{channels}{$channel}=1;
  return 1;
}

sub clientsHandler {
  my ($self,undef,$channel,$usersList)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{channels}{$channel}) {
    $sl->log("Ignoring CLIENTS command (non joined channel:\"$channel\")",1);
    return 0;
  }
  my @users=split(' ',$usersList);
  my @unknownUsers;
  foreach my $user (@users) {
    if(exists $self->{users}{$user}) {
      $self->{channels}{$channel}{users}{$user}=1;
      $self->{users}{$user}{channels}{$channel}=1;
    }else{
      push(@unknownUsers,$user);
    }
  }
  if(@unknownUsers) {
    $sl->log('Ignoring CLIENTS command (unknown user'.($#unknownUsers>0 ? 's' : '').': '.(join(',',@unknownUsers)).')',1);
    return 0;
  }
  return 1;
}

sub joinedHandler {
  my ($self,undef,$channel,$user)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{channels}{$channel}) {
    $sl->log("Ignoring JOINED command (non joined channel:\"$channel\")",1);
    return 0;
  }
  if(! exists $self->{users}{$user}) {
    $sl->log("Ignoring JOINED command (unknown user:\"$user\")",1);
    return 0;
  }
  if(exists $self->{channels}{$channel}{users}{$user}) {
    # The JOINED command shouldn't be sent to the joining user according to specs but most lobby servers do it anyway...
    if($user ne $self->{login}) {
      $sl->log("Ignoring JOINED command (user \"$user\" already in channel \"$channel\")",1);
      return 0;
    }
  }
  $self->{channels}{$channel}{users}{$user}=1;
  $self->{users}{$user}{channels}{$channel}=1;
  return 1;
}

sub leftHandler {
  my ($self,undef,$channel,$user)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{channels}{$channel}) {
    $sl->log("Ignoring LEFT command (non joined channel:\"$channel\")",1);
    return 0;
  }
  if(! exists $self->{users}{$user}) {
    $sl->log("Ignoring LEFT command (unknown user:\"$user\")",1);
    return 0;
  }
  if(! exists $self->{channels}{$channel}{users}{$user}) {
    $sl->log("Ignoring LEFT command (user \"$user\" not in channel \"$channel\")",1);
    return 0;
  }
  if($user eq $self->{login}) {
    delete $self->{channels}{$channel};
  }else{
    delete $self->{channels}{$channel}{users}{$user};
  }
  delete $self->{users}{$user}{channels}{$channel};
  return 1;
}

sub forceLeaveChannelHandler {
  my ($self,undef,$channel)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{channels}{$channel}) {
    $sl->log("Ignoring FORCELEAVECHANNEL command (non joined channel:\"$channel\")",1);
    return 0;
  }
  delete $self->{channels}{$channel};
  delete $self->{users}{$self->{login}}{channels}{$channel};
  return 1;
}

sub battleOpenedHandler {
  my ($self,undef,$battleId,$type,$natType,$founder,$ip,$port,$maxPlayers,$passworded,$rank,$mapHash,@otherParams)=@_;
  my $r_checkParamsRes=$self->checkIntParams('BATTLEOPENED',[qw/battleId type natType port maxPlayers passworded rank mapHash/],[\$battleId,\$type,\$natType,\$port,\$maxPlayers,\$passworded,\$rank,\$mapHash]);
  my $sl=$self->{conf}{simpleLog};
  if(exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring BATTLEOPENED command (duplicate battle:\"$battleId\")",1);
    return 0;
  }
  my $r_lobbyFounderData=$self->{users}{$founder};
  if(! defined $r_lobbyFounderData) {
    $sl->log("Ignoring BATTLEOPENED command (unknown founder:\"$founder\")",1);
    return 0;
  }
  if(defined $r_lobbyFounderData->{battleId}) {
    $sl->log("Ignoring BATTLEOPENED command (founder already in a battle:\"$founder\")",1);
    return 0;
  }
  $r_lobbyFounderData->{battleId}=$battleId;
  my ($engineName,$engineVersion,$map,$title,$mod);
  if($#otherParams < 4) {
    ($map,$title,$mod)=@otherParams;
    ($engineName,$engineVersion)=('spring',$self->{serverParams}{defaultSpringVersion});
    ($engineName,$engineVersion)=($1,$2) if($title =~ /^Incompatible \(([^ \)]+) +([^\)]+)\)/);
  }else{
    ($engineName,$engineVersion,$map,$title,$mod)=@otherParams;
  }
  $self->{battles}{$battleId} = { type => $type,
                                  natType => $natType,
                                  founder => $founder,
                                  ip => $ip,
                                  port => $port,
                                  maxPlayers => $maxPlayers,
                                  passworded => $passworded,
                                  rank => $rank,
                                  mapHash => $mapHash,
                                  engineName => $engineName,
                                  engineVersion => $engineVersion,
                                  map => $map,
                                  title => $title,
                                  mod => $mod,
                                  userList => [$founder],
                                  nbSpec => 0,
                                  locked => 0};
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub battleClosedHandler {
  my ($self,undef,$battleId)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring BATTLECLOSED command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  map {$self->{users}{$_}{battleId}=undef} (@{$self->{battles}{$battleId}{userList}});
  delete $self->{battles}{$battleId};
  $self->{battle}={} if(exists $self->{battle}{battleId} && $self->{battle}{battleId} == $battleId);
  return 1;
}

sub joinedBattleHandler {
  my ($self,undef,$battleId,$user,$scriptPass)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring JOINEDBATTLE command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  my $r_lobbyUserData=$self->{users}{$user};
  if(! defined $r_lobbyUserData) {
    $sl->log("Ignoring JOINEDBATTLE command (unknown user:\"$user\")",1);
    return 0;
  }
  if(defined $r_lobbyUserData->{battleId}) {
    $sl->log("Ignoring JOINEDBATTLE command (user is already in a battle:\"$user\")",1);
    return 0;
  }
  $r_lobbyUserData->{battleId}=$battleId;
  push(@{$self->{battles}{$battleId}{userList}},$user);
  if(exists $self->{battle}{battleId} && $battleId == $self->{battle}{battleId}) {
    $self->{battle}{users}{$user}={battleStatus => undef, color => undef, ip => undef, port => undef, scriptPass => $scriptPass, bots => {}};
  }
  return 1;
}

sub leftBattleHandler {
  my ($self,undef,$battleId,$user)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring LEFTBATTLE command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  my $r_lobbyUserData=$self->{users}{$user};
  if(! defined $r_lobbyUserData) {
    $sl->log("Ignoring LEFTBATTLE command (unknown user:\"$user\")",1);
    return 0;
  }
  if(! defined $r_lobbyUserData->{battleId}) {
    $sl->log("Ignoring LEFTBATTLE command (user is not in a battle:\"$user\")",1);
    return 0;
  }
  if($r_lobbyUserData->{battleId} != $battleId) {
    $sl->log("Ignoring LEFTBATTLE command (user is in a different battle:\"$user\")",1);
    return 0;
  }
  $r_lobbyUserData->{battleId}=undef;
  my @userList=@{$self->{battles}{$battleId}{userList}};
  my $userIndex=aindex(@userList,$user);
  splice(@userList,$userIndex,1);
  $self->{battles}{$battleId}{userList}=\@userList;
  my $rc=1;
  if(exists $self->{battle}{battleId} && $battleId == $self->{battle}{battleId}) {
    my $r_orphanBots=$self->{battle}{users}{$user}{bots};
    if(%{$r_orphanBots}) {
      $sl->log("Missing REMOVEBOT command before LEFTBATTLE (user \"$user\")",2);
      my @newBotList;
      map {push(@newBotList,$_) unless(exists $r_orphanBots->{$_})} @{$self->{battle}{botList}};
      $self->{battle}{botList}=\@newBotList;
      map {delete $self->{battle}{bots}{$_}} (keys %{$r_orphanBots});
      $rc=0;
    }
    delete $self->{battle}{users}{$user};
  }
  $self->{battle}={} if($user eq $self->{login});
  return $rc;
}

sub updateBattleInfoHandler {
  my ($self,undef,$battleId,$nbSpec,$locked,$mapHash,$map)=@_;
  my $r_checkParamsRes=$self->checkIntParams('UPDATEBATTLEINFO',[qw/battleId nbSpec locked mapHash/],[\$battleId,\$nbSpec,\$locked,\$mapHash]);
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring UPDATEBATTLEINFO command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  $self->{battles}{$battleId}{nbSpec}=$nbSpec;
  $self->{battles}{$battleId}{locked}=$locked;
  $self->{battles}{$battleId}{mapHash}=$mapHash;
  $self->{battles}{$battleId}{map}=$map;
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub openBattleHook {
  my $self=shift;
  $self->{password}=$_[3];
  $self->{openBattleModHash}=$_[6];
  return 1;
}

sub openBattleHandler {
  my ($self,undef,$battleId)=@_;
  my $r_checkParamsRes=$self->checkIntParams('OPENBATTLE',['battleId'],[\$battleId]);
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring OPENBATTLE command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  $self->{battle} = { battleId => $battleId,
                      users => {},
                      bots => {},
                      botList => [],
                      founder => $self->{battles}{$battleId}{founder},
                      restrictedUnits => {},
                      startRects => {},
                      scriptTags => {},
                      modHash => $self->{openBattleModHash},
                      password => $self->{password} };
  foreach my $user (@{$self->{battles}{$battleId}{userList}}) {
    $self->{battle}{users}{$user}={battleStatus => undef, color => undef, ip => undef, port => undef, bots => {}};
  }
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub joinBattleHook {
  my $self=shift;
  $self->{password}=$_[2];
  return 1;
}

sub joinBattleHandler {
  my ($self,undef,$battleId,$modHash)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battles}{$battleId}) {
    $sl->log("Ignoring JOINBATTLE command (unknown battle:\"$battleId\")",1);
    return 0;
  }
  $self->{battle} = { battleId => $battleId,
                      users => {},
                      bots => {},
                      botList => [],
                      founder => $self->{battles}{$battleId}{founder},
                      restrictedUnits => {},
                      startRects => {},
                      scriptTags => {},
                      modHash => $modHash,
                      password => $self->{password} };
  foreach my $user (@{$self->{battles}{$battleId}{userList}}) {
    $self->{battle}{users}{$user}={battleStatus => undef, color => undef, ip => undef, port => undef, bots => {}};
  }
  return 1;
}

sub joinBattleRequestHandler {
  my ($self,undef,$user,$ip)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{users}{$user}) {
    $sl->log("Ignoring JOINBATTLEREQUEST command (client \"$user\" offline)",1);
    return 0;
  }
  $self->{users}{$user}{ip}=$ip;
  return 1;
}

sub clientIpPortHandler {
  my ($self,undef,$user,$ip,$port)=@_;
  my $r_checkParamsRes=$self->checkIntParams('CLIENTIPPORT',['port'],[\$port]);
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{users}) {
    $sl->log("Ignoring CLIENTIPPORT command (currently out of any battle)",1);
    return 0;
  }
  if(! exists $self->{battle}{users}{$user}) {
    $sl->log("Ignoring CLIENTIPPORT command (client \"$user\" out of current battle)",1);
    return 0;
  }
  $self->{battle}{users}{$user}{ip}=$ip;
  $self->{battle}{users}{$user}{port}=$port;
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub clientBattleStatusHandler {
  my ($self,undef,$user,$battleStatus,$color)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{users}) {
    $sl->log("Ignoring CLIENTBATTLESTATUS command (currently out of any battle)",1);
    return 0;
  }
  if(! exists $self->{battle}{users}{$user}) {
    $sl->log("Ignoring CLIENTBATTLESTATUS command (client \"$user\" out of current battle)",1);
    return 0;
  }
  my $r_newClientBattleStatus=$self->unmarshallBattleStatus($battleStatus);
  if(! $self->{protocolExtensions}{'battleStatus:teams-8bit'} && defined $self->{battle}{users}{$user}{battleStatus}) {
    if(exists $self->{battle}{users}{$user}{battleStatus}{workaroundTeam}
       && $r_newClientBattleStatus->{team} % 16 == $self->{battle}{users}{$user}{battleStatus}{workaroundTeam} % 16) {
      $r_newClientBattleStatus->{workaroundTeam}=$self->{battle}{users}{$user}{battleStatus}{workaroundTeam};
      $r_newClientBattleStatus->{team}=$r_newClientBattleStatus->{workaroundTeam};
    }
    if(exists $self->{battle}{users}{$user}{battleStatus}{workaroundId}
       && $r_newClientBattleStatus->{id} % 16 == $self->{battle}{users}{$user}{battleStatus}{workaroundId} % 16) {
      $r_newClientBattleStatus->{workaroundId}=$self->{battle}{users}{$user}{battleStatus}{workaroundId};
      $r_newClientBattleStatus->{id}=$r_newClientBattleStatus->{workaroundId};
    }
  }
  $self->{battle}{users}{$user}{battleStatus}=$r_newClientBattleStatus;
  $self->{battle}{users}{$user}{color}=$self->unmarshallColor($color);
  return 1;
}

sub disableUnitsHandler {
  my ($self,undef,@units)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{restrictedUnits}) {
    $sl->log("Ignoring DISABLEUNITS command (currently out of any battle)",1);
    return 0;
  }
  @{$self->{battle}{restrictedUnits}}{@units} = (0) x @units;
  return 1;
}

sub enableUnitsHandler {
  my ($self,undef,@units)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{restrictedUnits}) {
    $sl->log("Ignoring ENABLEUNITS command (currently out of any battle)",1);
    return 0;
  }
  delete @{$self->{battle}{restrictedUnits}}{@units};
  return 1;
}

sub enableAllUnitsHandler  {
  my ($self,undef)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{restrictedUnits}) {
    $sl->log("Ignoring ENABLEALLUNITS command (currently out of any battle)",1);
    return 0;
  }
  $self->{battle}{restrictedUnits}={};
  return 1;
}

sub addBotHandler {
  my ($self,undef,$battleId,$name,$owner,$battleStatus,$color,$aiDll)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log("Ignoring ADDBOT command (currently out of any battle)",1);
    return 0;
  }
  if($battleId != $self->{battle}{battleId}) {
    $sl->log("Ignoring ADDBOT command (wrong battle ID:\"$battleId\")",1);
    return 0;
  }
  if(! exists $self->{users}{$owner}) {
    $sl->log("Ignoring ADDBOT command (unknown owner:\"$owner\")",1);
    return 0;
  }
  if(! exists $self->{battle}{users}{$owner}) {
    $sl->log("Ignoring ADDBOT command (owner \"$owner\" out of current battle)",1);
    return 0;
  }
  if(exists $self->{battle}{bots}{$name}) {
    $sl->log("Ignoring ADDBOT command (duplicate bot \"$name\")",1);
    return 0;
  }
  $self->{battle}{users}{$owner}{bots}{$name}=1;
  push(@{$self->{battle}{botList}},$name);
  $self->{battle}{bots}{$name} = { owner => $owner,
                                   battleStatus => $self->unmarshallBattleStatus($battleStatus),
                                   color => $self->unmarshallColor($color),
                                   aiDll => $aiDll };
  return 1;
}

sub removeBotHandler {
  my ($self,undef,$battleId,$name)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log("Ignoring REMOVEBOT command (currently out of any battle)",1);
    return 0;
  }
  if($battleId != $self->{battle}{battleId}) {
    $sl->log("Ignoring REMOVEBOT command (wrong battle ID:\"$battleId\")",1);
    return 0;
  }
  my @botList=@{$self->{battle}{botList}};
  my $botIndex=aindex(@botList,$name);
  if($botIndex == -1) {
    $sl->log("Ignoring REMOVEBOT command (unknown bot \"$name\")",1);
    return 0;
  }
  splice(@botList,$botIndex,1);
  $self->{battle}{botList}=\@botList;
  delete $self->{battle}{users}{$self->{battle}{bots}{$name}{owner}}{bots}{$name};
  delete $self->{battle}{bots}{$name};
  return 1;
}

sub updateBotHook {
  my ($self,$name,$marshalledStatus)=@_[0,2,3];

  return if($self->{protocolExtensions}{'battleStatus:teams-8bit'});
  
  my @workaroundStrings;
  if($marshalledStatus =~ /^(\d+)\((.+)\)$/) {
    $_[3]=$1;
    @workaroundStrings=split(/;/,$2);
  }
  
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log('Ignoring UPDATEBOT command sent by client (currently out of any battle)',1);
    return;
  }
  if(! exists $self->{battle}{bots}{$name}) {
    $sl->log("Ignoring UPDATEBOT command sent by client (unknown bot name \"$name\")",1);
    return;
  }
  
  delete $self->{battle}{bots}{$name}{battleStatus}{workaroundTeam};
  delete $self->{battle}{bots}{$name}{battleStatus}{workaroundId};
  foreach my $workaroundString (@workaroundStrings) {
    if($workaroundString =~ /^team=(\d+)$/) {
      my $teamNb=$1+0;
      $self->{battle}{bots}{$name}{battleStatus}{workaroundTeam}=$teamNb;
      $self->{battle}{bots}{$name}{battleStatus}{team}=$teamNb if($teamNb % 16 == $self->{battle}{bots}{$name}{battleStatus}{team} % 16);
    }elsif($workaroundString =~ /^id=(\d+)$/) {
      my $idNb=$1+0;
      $self->{battle}{bots}{$name}{battleStatus}{workaroundId}=$idNb;
      $self->{battle}{bots}{$name}{battleStatus}{id}=$idNb if($idNb % 16 == $self->{battle}{bots}{$name}{battleStatus}{id} % 16);
    }
  }
}

sub forceAllyNoHook {
  my ($self,$name,$teamNb)=@_[0,2,3];
  
  return if($self->{protocolExtensions}{'battleStatus:teams-8bit'});
  
  $teamNb+=0;
  $_[3]%=16;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log('Ignoring FORCEALLYNO command sent by client (currently out of any battle)',1);
    return;
  }
  if(! exists $self->{battle}{users}{$name}) {
    $sl->log("Ignoring FORCEALLYNO command sent by client (unknown user name \"$name\")",1);
    return;
  }
  return unless(defined $self->{battle}{users}{$name}{battleStatus});
  $self->{battle}{users}{$name}{battleStatus}{workaroundTeam}=$teamNb;
  $self->{battle}{users}{$name}{battleStatus}{team}=$teamNb if($teamNb % 16 == $self->{battle}{users}{$name}{battleStatus}{team} % 16);
}

sub forceTeamNoHook {
  my ($self,$name,$idNb)=@_[0,2,3];
  
  return if($self->{protocolExtensions}{'battleStatus:teams-8bit'});
  
  $idNb+=0;
  $_[3]%=16;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log('Ignoring FORCETEAMNO command sent by client (currently out of any battle)',1);
    return;
  }
  if(! exists $self->{battle}{users}{$name}) {
    $sl->log("Ignoring FORCETEAMNO command sent by client (unknown user name \"$name\")",1);
    return;
  }
  return unless(defined $self->{battle}{users}{$name}{battleStatus});
  $self->{battle}{users}{$name}{battleStatus}{workaroundId}=$idNb;
  $self->{battle}{users}{$name}{battleStatus}{id}=$idNb if($idNb % 16 == $self->{battle}{users}{$name}{battleStatus}{id} % 16);
}

sub updateBotHandler {
  my ($self,undef,$battleId,$name,$battleStatus,$color)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{battleId}) {
    $sl->log("Ignoring UPDATEBOT command (currently out of any battle)",1);
    return 0;
  }
  if($battleId != $self->{battle}{battleId}) {
    $sl->log("Ignoring UPDATEBOT command (wrong battle ID:\"$battleId\")",1);
    return 0;
  }
  if(! exists $self->{battle}{bots}{$name}) {
    $sl->log("Ignoring UPDATEBOT command (unknown bot name \"$name\")",1);
    return 0;
  }
  my $r_newBotBattleStatus=$self->unmarshallBattleStatus($battleStatus);
  if(! $self->{protocolExtensions}{'battleStatus:teams-8bit'} && defined $self->{battle}{bots}{$name}{battleStatus}) {
    if(exists $self->{battle}{bots}{$name}{battleStatus}{workaroundTeam}
       && $r_newBotBattleStatus->{team} % 16 == $self->{battle}{bots}{$name}{battleStatus}{workaroundTeam} % 16) {
      $r_newBotBattleStatus->{workaroundTeam}=$self->{battle}{bots}{$name}{battleStatus}{workaroundTeam};
      $r_newBotBattleStatus->{team}=$r_newBotBattleStatus->{workaroundTeam};
    }
    if(exists $self->{battle}{bots}{$name}{battleStatus}{workaroundId}
       && $r_newBotBattleStatus->{id} % 16 == $self->{battle}{bots}{$name}{battleStatus}{workaroundId} % 16) {
      $r_newBotBattleStatus->{workaroundId}=$self->{battle}{bots}{$name}{battleStatus}{workaroundId};
      $r_newBotBattleStatus->{id}=$r_newBotBattleStatus->{workaroundId};
    }
  }
  $self->{battle}{bots}{$name}{battleStatus}=$r_newBotBattleStatus;
  $self->{battle}{bots}{$name}{color}=$self->unmarshallColor($color);
  return 1;
}

sub addStartRectHandler {
  my ($self,undef,$id,$left,$top,$right,$bottom)=@_;
  my $r_checkParamsRes=$self->checkIntParams('ADDSTARTRECT',[qw/id left top right bottom/],[\$id,\$left,\$top,\$right,\$bottom]);
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{startRects}) {
    $sl->log("Ignoring ADDSTARTRECT command (currently out of any battle)",1);
    return 0;
  }
  $self->{battle}{startRects}{$id}={ left => $left, top => $top, right => $right, bottom => $bottom };
  return %{$r_checkParamsRes} ? 0 : 1;
}

sub removeStartRectHandler {
  my ($self,undef,$id)=@_;
  delete $self->{battle}{startRects}{$id};
  return 1;
}

sub setScriptTagsHandler {
  my ($self,undef,@scriptTags)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{scriptTags}) {
    $sl->log("Ignoring SETSCRIPTTAGS command (currently out of any battle)",1);
    return 0;
  }
  return 1 if(@scriptTags == 1 && $scriptTags[0] eq '');
  foreach my $tagValue (@scriptTags) {
    if($tagValue =~ /^\s*([^=]*[^=\s])\s*=\s*((?:.*[^\s])?)\s*$/) {
      $self->{battle}{scriptTags}{$1}=$2;
    }else{
      $sl->log("Ignoring invalid script tag in SETSCRIPTTAGS \"$tagValue\"",2);
    }
  }
  return 1;
}

sub removeScriptTagsHandler {
  my ($self,undef,@scriptTags)=@_;
  my $sl=$self->{conf}{simpleLog};
  if(! exists $self->{battle}{scriptTags}) {
    $sl->log("Ignoring REMOVESCRIPTTAGS command (currently out of any battle)",1);
    return 0;
  }
  foreach my $tag (@scriptTags) {
    if(exists $self->{battle}{scriptTags}{$tag}) {
      delete $self->{battle}{scriptTags}{$tag};
    }else{
      $sl->log("Ignoring unknown script tag in REMOVESCRIPTTAGS \"$tag\"",2);
    }
  }
  return 1;
}

1;
