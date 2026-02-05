rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 56 D1 60 0F B6 54 04 90 89 C6 21 D6 09 C2 } //Disrupt loop init
        $pattern1 = { 00 56 D1 A2 85 C0 74 06 E8 61 2E 7C 04 } //Influence conditional jump
        $pattern2 = { 00 56 D1 C7 E8 34 6F 88 74 CC } //Bypass key call

    condition:
        any of them
}