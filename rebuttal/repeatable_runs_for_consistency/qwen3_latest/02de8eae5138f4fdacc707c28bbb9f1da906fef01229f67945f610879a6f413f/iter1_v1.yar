rule Sample_Evasion
{
    meta:
        author = "CyberDefense"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        description = "Detects evasion techniques in a specific malware sample"
        date = "2023-10-05"
        version = "1.0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }  // Call to ExitProcess
        $pattern1 = { E8 ?? ?? ?? ?? }  // Call to CreateThread
        $pattern2 = { 81 C4 00 FC FF FF }  // Stack adjustment instruction

    condition:
        all of them
}