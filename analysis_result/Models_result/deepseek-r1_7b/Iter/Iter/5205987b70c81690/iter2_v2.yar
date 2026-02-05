rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific sequences leading to exit"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,action0=skip,bp2=$pattern2+0,action1=skip,bp3=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern0 = { [8B FF 55] }  # mov edi,edi followed by push ebp
        $pattern1 = { [E8 C8 FFFFFF FF7508 FF7508] }  # Call ExitProcess and two pushes
        $pattern2 = { [FF15ACB04100] }  # Final instruction before exit
}

condition:
    (any of the patterns match)