rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass the initial zero check (je)
        $pattern1 = { FF 15 2C A1 FA 00 33 FF 8B C7 EB 03 8D 43 01 } // Bypass the CALL 00FAA12Ch
        $pattern2 = { FF 15 AC B0 41 00 59 FF 75 08 } // Bypass the CALL 0041B0ACh

    condition:
        any of them
}