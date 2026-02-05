rule Bypass_Sample
{
    meta:
        description: "Evasion bypass rule targeting three decision points"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {
            8B45FCE5 + 0x3
            E8 ?? ?? ?? ??
            83C420 ?? ?? ?? ??
            FF15647D + 0x4
        }
        $pattern1 = {
            0049E87A + 0x0
            00C8F5FF + 0x0
            E83D2070 + 0x0
            FF15647D + 0x0
        }
        $pattern2 = {
            0049E87A + 0x0
            00C8F5FF + 0x0
            E83D2070 + 0x0
            FF15647D + 0x0
        }

    condition:
        any of them
}