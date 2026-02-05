rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 E8 ?? ?? ?? ?? }  // PUSH + CALL to ExitProcess
        $pattern1 = { 50 A1 ?? ?? ?? ?? 50 }  // PUSH + MEM + PUSH (context around ExitProcess)
        $pattern2 = { A1 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // MEM + CALL to sandbox check

    condition:
        any of them
}