rule ExitProcessCallAndStackSetup
{
    meta:
        description = "Detects the call to ExitProcess and associated stack setup."
        cape_options = "bp0=$call_exitprocess_1+0,action0=skip,bp1=$call_crtcor_1+0,action1=skip,bp2=$stack_setup+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-10"

    strings:
        // 1. Push [ebp+08h] followed by call to ExitProcess
        $call_exitprocess_1 = { FF 75 08 FF 15 ?? ?? ?? ?? }

        // 2. Push [ebp+08h] followed by call to _crtCorExitProcess
        $call_crtcor_1 = { FF 75 08 E8 ?? ?? ?? ?? }

        // 3. Stack setup (push ebp, mov ebp, esp, push [ebp+08h])
        $stack_setup = { 55 8B EC FF 75 08 }

    condition:
        all of ($call_exitprocess_1, $call_crtcor_1, $stack_setup)
}