rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection rules targeting various stack manipulation points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 08 ?? ?? ?? ?? }   // Standard bypass with known function call
        $pattern1 = { 55 8B EC E8 FF ?? 00 00 00 30 } // Divergent stack usage before unknown address
        $pattern2 = { 6A 40 53 5B FF 75 08 FF 15 AC B0 41 01 59 FF 75 08 E8 FF ?? FF 15 40 E1 1F 01 } // Complex bypass in fifth trace
    condition:
        any_of_them
}