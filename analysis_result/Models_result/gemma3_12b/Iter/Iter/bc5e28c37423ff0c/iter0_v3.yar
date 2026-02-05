rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 } // Skip CALL [ESI] - 11 bytes
        $pattern1 = { 8B 45 08 8B 48 14 56 6A 35 6A 00 51 } // Modify ESI - 13 bytes
        $pattern2 = { 50 51 8B 06 83 C4 14 } // Modify EAX - 10 bytes

    condition:
        any of them
}