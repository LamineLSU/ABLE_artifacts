rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focuses on early exit conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [6 -2 0 BY TE S WI TH EX AC T HE X VA LU ES ] }
        $pattern1 = { [6 -2 0 BY TE S - DI FF ER EN T SE QU EN CE ] }
        $pattern2 = { [6 -2 0 BY TE S - DI FF ER EN T SE QU EN CE ] }

    condition:
        any of them
}