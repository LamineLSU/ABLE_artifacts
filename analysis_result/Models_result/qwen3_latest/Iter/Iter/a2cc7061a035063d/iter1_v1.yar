rule ExitProcessDetection
{
    meta:
        description = "Detects calls to ExitProcess and related evasion checks"
        cape_options = "bp0=$call_crtcor+0,action0=skip,bp1=$call_exitprocess+0,action1=skip,bp2=$ebp_setup+0,action2=skip,count=0"
        author = "Security Analyst"
    
    strings:
        $call_crtcor = { E8 ?? ?? ?? ?? 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $call_exitprocess = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push ebp+08h followed by call to ExitProcess
        $ebp_setup = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // EBP setup, push ebp+08h, and call to ___crtCorExitProcess
    
    condition:
        any of them
}