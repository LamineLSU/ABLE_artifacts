rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instructions near critical points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [6 -2 0 BY TE S WI TH EX AC T HE X] }
        $pattern1 = { [6 -2 0 BY TE S WI TH EX AC T HE X] }
        $pattern2 = { [6 -2 0 BY TE S WI TH EX AC T HE X] }

    condition:
        any of them
}