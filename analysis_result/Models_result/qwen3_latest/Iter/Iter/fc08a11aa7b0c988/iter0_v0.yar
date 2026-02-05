rule SandboxEvasionDetector
{
    meta:
        author = "CyberDefenseAnalyst"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        description = "Detects sandbox evasion techniques via function calls and conditional checks"

    strings:
        $pattern0 = { FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 10 }  // IsWindowVisible check and conditional jump
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }        // ExitProcess call and adjacent function calls
        $pattern2 = { 6A 02 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? }          // Shell_NotifyIconA call and string push

    condition:
        any of them
}