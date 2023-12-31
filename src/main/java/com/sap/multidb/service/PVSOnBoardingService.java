package com.sap.multidb.service;

//@Service
public class PVSOnBoardingService {

//    @Autowired
//    ObjectMapper objMapper;
//
//    @Autowired
//    HanaInstanceManagerConnector hanaInstanceManagerConnector;
//
//    private final String visibilityFlywayScriptsLocation = "classpath:db/flyway-tenant/hana/visibility";
//
//    Logger logger = LoggerFactory.getLogger(PVSOnBoardingService.class);
//
//    public String createManagedInstance(final String tenantId, final DataSource dataSource,
//            final TenantContext tenantContext) {
//
//        ManagedServiceInstance managedInstance = null;
//
//        boolean instanceExists = hanaInstanceManagerConnector.doesInstanceExist(tenantId);
//
//        if (instanceExists) {
//            return "already exists";
//        }
//
//        try {
//            managedInstance = hanaInstanceManagerConnector.createManagedInstance(tenantId);
//        } catch (PVSManagedHanaInstanceException e) {
//            return "Error during creation";
//        }
//
//        OperationStatus status = managedInstance.getStatus();
//
//        if (status.equals(OperationStatus.CREATION_SUCCEEDED)) {
//            triggerFlyway(tenantContext, tenantId, dataSource);
//        }
//
//        return "Operation Sucessful with Status : " + status.toString();
//    }
//
//    public String getVisibilityFlywayScriptsLocation() {
//        return visibilityFlywayScriptsLocation;
//    }
//
//    private void triggerFlyway(final TenantContext tenantContext, final String tenantId, final DataSource dataSource) {
//        logger.info("Start Flyway");
//        tenantContext.setCurrentTenant(tenantId);
//        try (Connection connection = dataSource.getConnection();) {
//
//            String currentHDI = System.getenv("HANA_FOR_ONBOARDING");
//            VcapServiceReader vcapServiceReader = new VcapServiceReader();
//
//            String bpmpvHanaSchemaUser = (String) vcapServiceReader.getAttribute(currentHDI, "user");
//            String tenantSchema = connection.getSchema();
//
//            Map<String, String> placeholders = new HashMap<>();
//            placeholders.put("tenantSchema", tenantSchema);
//            placeholders.put("bpmpvHanaSchemaUser", bpmpvHanaSchemaUser);
//
//            Flyway flyway = new Flyway();
//            flyway.setDataSource(dataSource);
//            flyway.setLocations(getVisibilityFlywayScriptsLocation());
//            flyway.setPlaceholders(placeholders);
//            flyway.setSkipDefaultCallbacks(true);
//            flyway.migrate();
//
//        } catch (RuntimeException | SQLException e) {
//
//            logger.info("Flyway deployment didnt trigger");
//            logger.info(e.getMessage());
//        }
//    }
}