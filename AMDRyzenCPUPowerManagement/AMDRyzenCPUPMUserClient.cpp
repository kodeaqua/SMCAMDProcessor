//
//  AMDRyzenCPUPowerManagementUserClient.cpp
//  AMDRyzenCPUPowerManagement
//
//  Created by trulyspinach on 2/4/20.
//

#include "AMDRyzenCPUPMUserClient.hpp"



OSDefineMetaClassAndStructors(AMDRyzenCPUPMUserClient, IOUserClient);


bool AMDRyzenCPUPMUserClient::initWithTask(task_t owningTask,
                                             void *securityToken,
                                             UInt32 type,
                                             OSDictionary *properties){
    
    if(!IOUserClient::initWithTask(owningTask, securityToken, type, properties)){
        return false;
    }
    
    token = securityToken;
    
    proc_t proc = (proc_t)get_bsdtask_info(owningTask);
    proc_name(proc_pid(proc), taskProcessBinaryName, 32);
    clientAuthorizedByUser = false;
    

    
    return true;

}

bool AMDRyzenCPUPMUserClient::start(IOService *provider){
    
    IOLog("AMDCPUSupportUserClient::start\n");
    
    bool success = IOService::start(provider);
    
    if(success){
        fProvider = OSDynamicCast(AMDRyzenCPUPowerManagement, provider);
    }
    
    return success;
}

void AMDRyzenCPUPMUserClient::stop(IOService *provider){
    IOLog("AMDCPUSupportUserClient::stop\n");
    
    fProvider = nullptr;
    IOService::stop(provider);
}

//this is a meme, not getting the joke? nvm.
uint64_t multiply_two_numbers(uint64_t number_one, uint64_t number_two){
    uint64_t number_three = 0;
    for(uint32_t i = 0; i < number_two; i++){
        number_three = number_three + number_one;
    }
    return number_three;
}

bool AMDRyzenCPUPMUserClient::hasPrivilege(){
    if(fProvider->disablePrivilegeCheck) return true;
    if(clientHasPrivilege(token, kIOClientPrivilegeAdministrator) == kIOReturnSuccess) return true;
    if(clientAuthorizedByUser) return true;

    if(!fProvider->kunc_alert){
        //_KUNCUserNotificationDisplayAlert wasn't found at symbol-resolution time
        //(happens on some macOS versions -- see AMDRyzenCPUPowerManagement::start).
        //There's no way to prompt the user, so fail closed instead of calling a
        //NULL function pointer.
        IOLog("AMDCPUSupportUserClient::hasPrivilege kunc_alert unavailable, denying\n");
        return false;
    }

    char buf[128];
    snprintf(buf, 128,
             "A process is trying to make changes to your system.\nAffected process name: %s\n\nAuthorize?",
             taskProcessBinaryName);
    
    unsigned int rf;
    (*(fProvider->kunc_alert))(0, 0, NULL, NULL, NULL,
                  "AMDRyzenCPUPowerManagement", buf, "Deny", "Until Process Terminate", "Once", &rf);
    
    
    if(rf == 1){
        clientAuthorizedByUser = true;
        return true;
    }
    
    if(rf == 2){
        return true;
    }
    
    return false;
}

IOReturn AMDRyzenCPUPMUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                                 IOExternalMethodDispatch *dispatch,
                                                   OSObject *target, void *reference){

    if(!fProvider) return kIOReturnNotAttached;

    //externalMethod() is overridden directly instead of going through a
    //checked IOExternalMethodDispatch table, so IOKit does *not* validate
    //structureOutputSize against what the caller actually allocated -- every
    //case below used to just overwrite arguments->structureOutputSize with
    //whatever it felt like returning and write that many bytes into
    //arguments->structureOutput, regardless of the buffer's real capacity
    //(the value structureOutputSize holds on entry). Any unprivileged local
    //process could call e.g. selector 2 with a tiny output buffer and get a
    //kernel heap overflow written with driver-controlled data. Capture the
    //real capacity up front and make every variable-size case check against
    //it before writing.
    const uint32_t outCapacity = arguments->structureOutput ? arguments->structureOutputSize : 0;

    if (fProvider->kextloadAlerts && fProvider->kunc_alert) {
        unsigned int rf;

        char buf[128];
        snprintf(buf, 128,
                 "Kext alert detected: %d",
                 fProvider->kextloadAlerts);

        (*(fProvider->kunc_alert))(0, 0, NULL, NULL, NULL,
                      "AMDRyzenCPUPowerManagement", buf, "Ok", "Ok and Clear Alert", "WTF?", &rf);
        if(rf == 1){
            fProvider->kextloadAlerts = 0;
        }
    }
    
    fProvider->registerRequest();
    
    switch (selector) {
            
        //Get PStateDef raw values for core 0
        case 0: {
            uint32_t needed = (fProvider->kMSR_PSTATE_LEN) * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            for(uint32_t i = 0; i < fProvider->kMSR_PSTATE_LEN; i++){
                dataOut[i] = fProvider->PStateDef_perCore[i];
            }

            break;
        }
            
            
        //Get PStateDef floating point clock values for core 0
        case 1: {
            uint32_t needed = (fProvider->kMSR_PSTATE_LEN) * sizeof(float);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            float *dataOut = (float*) arguments->structureOutput;

            for(uint32_t i = 0; i < fProvider->kMSR_PSTATE_LEN; i++){
                dataOut[i] = fProvider->PStateDefClock_perCore[i];
            }

            break;
        }
            
        case 2: {

            uint32_t numPhyCores = fProvider->totalNumberOfPhysicalCores;
            uint32_t needed = numPhyCores * sizeof(float);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 1;
            arguments->scalarOutput[0] = numPhyCores;

            arguments->structureOutputSize = needed;

            float *dataOut = (float*) arguments->structureOutput;

            for(uint32_t i = 0; i < numPhyCores; i++){
                dataOut[i] = fProvider->effFreq_perCore[i];
            }

            break;
        }

        case 3: {
            uint32_t needed = 1 * sizeof(float);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            float *dataOut = (float*) arguments->structureOutput;
            dataOut[0] = fProvider->PACKAGE_TEMPERATURE_perPackage[0];
            break;
        }
        
        //Get all data like this: [power, temp, pstateCur, clock_core_1, 2, 3 .....]
        //Yes, i am too lazy to write a struct
        case 4: {
            uint32_t numPhyCores = fProvider->totalNumberOfPhysicalCores;
            uint32_t needed = (numPhyCores + 3) * sizeof(float);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 1;
            arguments->scalarOutput[0] = numPhyCores;

            arguments->structureOutputSize = needed;

            float *dataOut = (float*) arguments->structureOutput;
            
            dataOut[0] = (float)fProvider->uniPackageEnergy;
            dataOut[1] = fProvider->PACKAGE_TEMPERATURE_perPackage[0];
            dataOut[2] = fProvider->PStateCtl;
            
            for(uint32_t i = 0; i < numPhyCores; i++){
                dataOut[i + 3] = fProvider->effFreq_perCore[i];
            }
            
            break;
        }
            
        //Get per core raw load index
        case 5: {
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = 0;

            for(uint32_t i = 0; i < fProvider->totalNumberOfLogicalCores; i++){
                dataOut[0] += fProvider->instructionDelta_perCore[i];
            }

            break;
        }

        //Get per core load index
        case 6: {
            if(fProvider->totalNumberOfPhysicalCores == 0)
                return kIOReturnNotReady;

            uint32_t needed = (fProvider->totalNumberOfPhysicalCores) * sizeof(float);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            float *dataOut = (float*) arguments->structureOutput;

            int lcpu_percore = fProvider->totalNumberOfLogicalCores / fProvider->totalNumberOfPhysicalCores;
            
            for(uint32_t i = 0; i < fProvider->totalNumberOfPhysicalCores; i++){
                float l = pmRyzen_avgload_pcpu(i * lcpu_percore);
//                dataOut[i] = fProvider->loadIndex_PerCore[i];
                dataOut[i] = l;
            }
            
            break;
        }
            
        //Get basic CPUID
        //[Family, Model, Physical, Logical, L1_perCore, L2_perCore, L3]
        case 7: {
            uint32_t needed = (8) * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)fProvider->cpuFamily;
            dataOut[1] = (uint64_t)fProvider->cpuModel;
            dataOut[2] = (uint64_t)fProvider->totalNumberOfPhysicalCores;
            dataOut[3] = (uint64_t)fProvider->totalNumberOfLogicalCores;
            dataOut[4] = (uint64_t)fProvider->cpuCacheL1_perCore;
            dataOut[5] = (uint64_t)fProvider->cpuCacheL2_perCore;
            dataOut[6] = (uint64_t)fProvider->cpuCacheL3;
            dataOut[7] = (uint64_t)fProvider->cpuSupportedByCurrentVersion;
            
            break;
        }
        
        //Get AMDRyzenCPUPowerManagement Version String
        case 8: {
            uint32_t needed = sizeof(xStringify(MODULE_VERSION));
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;
            char *dataOut = (char*) arguments->structureOutput;

            for(uint32_t i = 0; i < arguments->structureOutputSize; i++){
                dataOut[i] = xStringify(MODULE_VERSION)[i];
            }

            break;
        }

        //Get PState
        case 9: {
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = fProvider->PStateCtl;

            break;
        }
        
        //Set PState
        case 10: {
            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = 0;

            if(!hasPrivilege())
                return kIOReturnNotPrivileged;

            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;

            fProvider->PStateCtl = (uint8_t)arguments->scalarInput[0];
            fProvider->applyPowerControl();
            break;
        }
            
        //Get CPB
        case 11: {
            uint32_t needed = 2 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)fProvider->cpbSupported;
            dataOut[1] = (uint64_t)fProvider->getCPBState();
            break;
        }
        
        //Set CPB
        case 12: {
            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = 0;

            if(!hasPrivilege())
                return kIOReturnNotPrivileged;

            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;

            if(!fProvider->cpbSupported)
                return kIOReturnNoDevice;

            fProvider->setCPBState(arguments->scalarInput[0]==1?true:false);
            
            break;
        }
            
        //Get PPM
        case 13: {
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)(fProvider->getPMPStateLimit() == 0 ? 0 : 1);
            break;
        }
            
        //Set PPM
        case 14: {
            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = 0;

            if(!hasPrivilege())
                return kIOReturnNotPrivileged;

            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;

            boolean_t enabled = arguments->scalarInput[0]==1?true:false;

            fProvider->setPMPStateLimit(enabled ? 1 : 0);
            
            break;
        }
            
        //Set PStateDef
        case 15: {
            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = 0;

            if(!hasPrivilege())
                return kIOReturnNotPrivileged;

            if(arguments->scalarInputCount != 8)
                return kIOReturnBadArgument;


            fProvider->writePstate(arguments->scalarInput);

            break;
        }
            
        //get board info
        case 16: {
            uint32_t needed = 128;
            if(needed > outCapacity) return kIOReturnBadArgument;

            //Let's give that one more try :)
            if(!fProvider->boardInfoValid)
                fProvider->fetchOEMBaseBoardInfo();

            arguments->scalarOutputCount = 1;
            arguments->scalarOutput[0] = fProvider->boardInfoValid ? 1 : 0;

            arguments->structureOutputSize = needed;

            char *dataOut = (char*) arguments->structureOutput;
            
            for(uint32_t i = 0; i < 64; i++){
                dataOut[i] = fProvider->boardVender[i];
            }
            
            for(uint32_t i = 0; i < 64; i++){
                dataOut[i+64] = fProvider->boardName[i];
            }
            
            break;
        }
            
        case 17: {
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)(fProvider->getHPcpus());
            break;
        }

        //Get LPM
        case 18: {
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;

            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)(fProvider->getPMPStateLimit() == 2 ? 1 : 0);
            break;
        }
            
        //Set LPM
        case 19: {
            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = 0;

            if(!hasPrivilege())
                return kIOReturnNotPrivileged;

            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;

            boolean_t enabled = arguments->scalarInput[0]==1?true:false;

            fProvider->setPMPStateLimit(enabled ? 2 : 1);
            
            break;
        }
        
        //Try load SMC driver
        case 90: {
            uint32_t needed = 2 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;
            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;
            
            if(fProvider->superIO != nullptr){
                dataOut[0] = (uint64_t)(1);
                dataOut[1] = (uint64_t)(fProvider->savedSMCChipIntel);
                break;
            }
            
            uint16_t ci = 0;
            bool found = fProvider->initSuperIO(&ci);
            
            dataOut[0] = (uint64_t)(found ? 1 : 0);
            dataOut[1] = (uint64_t)(ci);
            break;
        }
        
        //SMC load number of fans
        case 91: {
            
            if(!fProvider->superIO)
                return kIOReturnNoDevice;

            
            uint32_t needed = 1 * sizeof(uint64_t);
            if(needed > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed;
            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            dataOut[0] = (uint64_t)(fProvider->superIO->getNumberOfFans());
            break;
        }
        
        //SMC load readable desc for fan
        case 92: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;

            arguments->scalarOutputCount = 0;
                
            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;
                
            
            const char *str = fProvider->superIO->getReadableStringForFan((int)arguments->scalarInput[0]);
            if(!str)
                return kIOReturnBadArgument;

            //strcpy(dest, src, len) (see MacKernelSDK/Headers/string.h) is a
            //macro that silently discards `len` and expands to
            //__builtin___strcpy_chk, whose bound comes from
            //__builtin_object_size(dest, 1) -- unknowable for a plain
            //pointer like dataOut, so it gave no real overflow protection.
            //strlcpy actually honors the length we pass it.
            static constexpr uint32_t kMaxFanNameLen = 64;
            uint32_t len = (uint32_t)strlen(str);
            if(len > kMaxFanNameLen - 1) len = kMaxFanNameLen - 1;
            //Also respect the caller's actual output buffer capacity --
            //kMaxFanNameLen is just our own sanity cap, not a guarantee the
            //caller allocated that much.
            if(len >= outCapacity) return kIOReturnBadArgument;
            arguments->structureOutputSize = len;

            char *dataOut = (char*) arguments->structureOutput;
            strlcpy(dataOut, str, len + 1);


            break;
        }
            
        //SMC fan rpms
        case 93: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;
            
            uint32_t needed93 = fProvider->superIO->getNumberOfFans() * sizeof(uint64_t);
            if(needed93 > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed93;
            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            fProvider->superIO->updateFanRPMS();
            for (int i = 0; i < fProvider->superIO->getNumberOfFans(); i++) {
                dataOut[i] = fProvider->superIO->getRPMForFan(i);
            }
            
            break;
        }
            
        default: {
            IOLog("AMDCPUSupportUserClient::externalMethod: invalid method.\n");
            break;
        }
        
        //SMC fan throttles and control mode
        case 94: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;
            
            uint32_t needed94 = fProvider->superIO->getNumberOfFans() * sizeof(uint64_t);
            if(needed94 > outCapacity) return kIOReturnBadArgument;

            arguments->scalarOutputCount = 0;
            arguments->structureOutputSize = needed94;
            uint64_t *dataOut = (uint64_t*) arguments->structureOutput;

            fProvider->superIO->updateFanControl();
            for (int i = 0; i < fProvider->superIO->getNumberOfFans(); i++) {
                dataOut[i] = fProvider->superIO->getFanThrottle(i) << 8 | (fProvider->superIO->getFanAutoControlMode(i) ? 1 : 0);
            }
            
            break;
        }
        
        //SMC fan overrride control
        case 95: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;
            
            if(!hasPrivilege())
                return kIOReturnNotPrivileged;
            
            if(arguments->scalarInputCount != 2)
                return kIOReturnBadArgument;
            
            int fanSel = (int)arguments->scalarInput[0];
            uint8_t pwm = (uint8_t)arguments->scalarInput[1];
            
            fProvider->superIO->overrideFanControl(fanSel, pwm);
            
            break;
        }
        
        //SMC fan default control
        case 96: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;
            
            if(!hasPrivilege())
                return kIOReturnNotPrivileged;
            
            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;
            
            int fanSel = (int)arguments->scalarInput[0];
            
            fProvider->superIO->setDefaultFanControl(fanSel);
            
            break;
        }
        
        //SMC Secret Undocumented feature (⁎⁍̴̛ᴗ⁍̴̛⁎)
        case 97: {
            if(!fProvider->superIO)
                return kIOReturnNoDevice;
            
            if(!hasPrivilege())
                return kIOReturnNotPrivileged;
            
            if(arguments->scalarInputCount != 1)
                return kIOReturnBadArgument;
            
            int numFan = fProvider->superIO->getNumberOfFans();
            for (int i = 0; i < numFan; i++) {
                if(arguments->scalarInput[0])
                    fProvider->superIO->overrideFanControl(i, 0xff);
                else
                    fProvider->superIO->setDefaultFanControl(i);
            }
            
            break;
        }
    }
    
    return kIOReturnSuccess;
}
