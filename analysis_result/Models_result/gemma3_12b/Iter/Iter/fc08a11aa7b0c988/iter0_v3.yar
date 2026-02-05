rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 B0 5B 41 00 6A 02 FF 15 C4 03 41 00 } //Bypass Conditional Check
        $pattern1 = { FF 15 24 01 41 00 FF 15 30 04 41 00 } //Bypass Call Before ExitProcess
        $pattern2 = { FF 35 AC 5B 41 00 FF 15 0C 04 41 00 } //Bypass Check involving 00415BACh

    condition:
        any of them
}