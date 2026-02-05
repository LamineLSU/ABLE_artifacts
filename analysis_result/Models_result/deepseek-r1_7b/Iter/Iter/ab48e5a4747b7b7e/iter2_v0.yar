rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked API calls"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 5F 73 00 00 00 00 ?? ?? }  // Specific call to API function
        $pattern1 = { FF 75 08 00 00 00 00 FF 75 08 }  // Double push to dword ptr [ebp+08h]
        $pattern2 = { E8 C8 FF FF FF FF FF FF FF FF }  // Conditional call before exit
}

condition:
    (match $pattern0) || (match $pattern1) || (match $pattern2)