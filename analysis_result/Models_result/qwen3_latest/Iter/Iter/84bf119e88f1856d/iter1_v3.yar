rule SampleCodePattern
{
    meta:
        description = "Detects code that makes a call to ExitProcess and related CRT functions"
        cape_options = "bp0=$call_to_exitprocess+0,action0=skip,bp1=$call_to_crtcor_exitprocess+0,action1=skip,bp2=$push_and_call+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        // 1. Call to ExitProcess (specific address)
        $call_to_exitprocess = { FF 15 AC B0 41 00 }

        // 2. Call to ___crtCorExitProcess followed by a pop ecx
        $call_to_crtcor_exitprocess = { E8 C8 FF FF FF 59 }

        // 3. Push [ebp+08h] followed by call to ExitProcess
        $push_and_call = { FF 75 08 FF 15 AC B0 41 00 }

    condition:
        all of ($call_to_exitprocess, $call_to_crtcor_exitprocess, $push_and_call)
}