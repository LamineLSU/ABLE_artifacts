rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 43 F6 70 43 35 92 8D 56 FC 74 7D 55 8B } // Skips div instruction and checks for je. 17 bytes
        $pattern1 = { 52 8B 16 50 51 FF D2 5E 5D C3 FF D0 } // Skips CALL EAX. 16 bytes
        $pattern2 = { 35 92 8D 56 FC 74 7D 55 8B 45 08 8B } // Skips XOR and related instructions. 16 bytes

    condition:
        any of them
}