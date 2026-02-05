rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific setup before ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [0x40e7ec: 8BFF558BECFF7508] }
        $pattern1 = { [0x40e7fc: 83F80174128B4DF8] }
        $pattern2 = { [0x40e803: 33FFC003] }

    condition:
        (any($pattern0) || any($pattern1) || any($pattern2))
}