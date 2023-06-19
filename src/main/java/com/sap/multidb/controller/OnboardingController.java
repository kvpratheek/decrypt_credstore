package com.sap.multidb.controller;

import org.springframework.web.bind.annotation.RestController;

@RestController
public class OnboardingController {

//    @Autowired
//    TenantAwareDataSource dataSource;
//
//    @Autowired
//    PVSOnBoardingService onboardingService;
//
//    @Autowired
//    TenantContext tenantContext;
//
////    @Autowired
////    TenantDetailsRepo tenantRepo;
//
//    private final Logger logger = LoggerFactory.getLogger(this.getClass());
//
//    @PostMapping("/onboard")
//    public String onBoardTenant(@RequestParam(name = "tenantId") final String tenantId, @RequestBody final TenantDetails tenantDetails) {
//
//        logger.info("OnBoarding Started with " + tenantId);
//        tenantContext.setCurrentTenant(tenantId);
//        System.out.println(tenantDetails.toString());
////        saveTenantDetails(tenantDetails);
//        return onboardingService.createManagedInstance(tenantId, dataSource, tenantContext);
//
//    }
//
////    @Transactional("applicationSchemaTransactionManager")
////    public TenantDetails saveTenantDetails(final TenantDetails tenantDetail) {
////
////        return tenantRepo.save(tenantDetail);
////
////    }

}
