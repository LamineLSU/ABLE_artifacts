rule Bypass_Evasion
{
    meta:
        description = "Bypass analysis for x64 malware traces exiting via ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC F7 50 8E 8C 8F FF FF F5 9F F1 5A CB 04 10 }
        $pattern1 = { E8 C8 FF FF FF 59 FF 15 AC B0 41 00 83 C4 ?? ?? ?? ?? 85 C0 0F 84 ?? }
        $pattern2 = { FF 75 08 E8 C8 FF FF FF 59 FF 15 AC B0 41 00 85 C0 0F 84 ?? }

    condition:
        any of them
}