rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 64 A1 30 00 00 00 8B 40 68 C1 E8 08 } //Bypass FS check (11 bytes)
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 FF 15 40 30 2E 01 } //Skip first API call (10 bytes)
        $pattern2 = { 83 F8 01 74 20 FF 15 44 30 2E 01 } //Skip conditional jump (9 bytes)

    condition:
        any of them
}