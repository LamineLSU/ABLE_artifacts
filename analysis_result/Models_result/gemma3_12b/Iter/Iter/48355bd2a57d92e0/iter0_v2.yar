rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 B8 00 } //Trace 1, skipping call to function
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 FF 15 08 A1 B8 00 } //Trace 2, skipping conditional jump
        $pattern2 = { 8B FF 55 8B EC E8 6A 3E 00 00 84 C0 74 20 FF 15 08 A1 B8 00 } //Trace 2, skipping check and call

    condition:
        any of them
}