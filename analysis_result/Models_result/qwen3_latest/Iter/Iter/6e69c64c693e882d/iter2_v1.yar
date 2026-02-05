rule crt_cor_exit_call {
    meta:
        author = "CyberSecurityTeam"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        description = "Detects the CRT-coroutine exit call pattern in malicious code"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? } // push ebp+08h followed by call to ___crtCorExitProcess
        $b = { E8 ?? ?? ?? ?? 59 FF 75 08 } // call to ___crtCorExitProcess, pop ecx, push ebp+08h
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? } // push ebp+08h followed by call to ExitProcess
    condition:
        $a or $b or $c
}