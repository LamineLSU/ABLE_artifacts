rule FunctionCallSetup
{
    meta:
        description = "Detects function call setup and cleanup in a stack-based function"
        cape_options = "bp0=$push_call1+0,action0=skip,bp1=$push_call2+0,action1=skip,bp2=$ebp_setup+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-25"

    strings:
        $push_call1 = { FF 75 08 E8 C8 FF FF FF } // push [ebp+08h], call ___crtCorExitProcess
        $push_call2 = { FF 75 08 FF 15 AC B0 41 00 } // push [ebp+08h], call ExitProcess
        $ebp_setup = { 55 8B EC } // push ebp, mov ebp, esp

    condition:
        all of them
}