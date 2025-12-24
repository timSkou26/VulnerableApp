package org.sasanlabs.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.lang.reflect.Method;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.sasanlabs.beans.AllEndPointsResponseBean;
import org.sasanlabs.beans.AttackVectorResponseBean;
import org.sasanlabs.beans.LevelResponseBean;
import org.sasanlabs.beans.ScannerResponseBean;
import org.sasanlabs.configuration.VulnerableAppProperties;
import org.sasanlabs.internal.utility.EnvUtils;
import org.sasanlabs.internal.utility.FrameworkConstants;
import org.sasanlabs.internal.utility.GenericUtils;
import org.sasanlabs.internal.utility.MessageBundle;
import org.sasanlabs.internal.utility.annotations.AttackVector;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRequestMapping;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRestController;
import org.sasanlabs.service.IEndPointsInformationProvider;
import org.sasanlabs.vulnerableapp.facade.schema.ResourceInformation;
import org.sasanlabs.vulnerableapp.facade.schema.ResourceType;
import org.sasanlabs.vulnerableapp.facade.schema.ResourceURI;
import org.sasanlabs.vulnerableapp.facade.schema.Variant;
import org.sasanlabs.vulnerableapp.facade.schema.VulnerabilityDefinition;
import org.sasanlabs.vulnerableapp.facade.schema.VulnerabilityLevelDefinition;
import org.sasanlabs.vulnerableapp.facade.schema.VulnerabilityLevelHint;
import org.sasanlabs.vulnerableapp.facade.schema.VulnerabilityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** @author KSASAN */
@Service
public class EndPointsInformationProvider implements IEndPointsInformationProvider {

    private EnvUtils envUtils;
    private MessageBundle messageBundle;
    private VulnerableAppProperties vulnerableAppProperties;
    int port;

    // ======================================================
    // ΔΙΟΡΘΩΣΗ 1:
    // Σταθερά για αποφυγή επανάληψης string literal
    // ======================================================
    private static final String TEMPLATE_BASE_PATH = "/VulnerableApp/templates/";

    public EndPointsInformationProvider(
            EnvUtils envUtils,
            MessageBundle messageBundle,
            VulnerableAppProperties vulnerableAppProperties,
            @Value("${server.port}") int port) {
        this.envUtils = envUtils;
        this.messageBundle = messageBundle;
        this.vulnerableAppProperties = vulnerableAppProperties;
        this.port = port;
    }

    // ======================================================
    // ΠΑΛΙΟΣ ΚΩΔΙΚΑΣ (σε σχόλια)
    // Υψηλό Cognitive Complexity (~35)
    // ======================================================
    /*
    @Override
    public List<VulnerabilityDefinition> getVulnerabilityDefinitions()
            throws JsonProcessingException {

        List<VulnerabilityDefinition> vulnerabilityDefinitions = new ArrayList<>();
        Map<String, Object> endpoints =
                envUtils.getAllClassesAnnotatedWithVulnerableAppRestController();

        for (Map.Entry<String, Object> entry : endpoints.entrySet()) {
            Class<?> clazz = entry.getValue().getClass();

            if (clazz.isAnnotationPresent(VulnerableAppRestController.class)) {

                VulnerableAppRestController controller =
                        clazz.getAnnotation(VulnerableAppRestController.class);

                VulnerabilityDefinition definition = new VulnerabilityDefinition();
                definition.setName(entry.getKey());
                definition.setId(entry.getKey());
                definition.setDescription(
                        messageBundle.getString(controller.descriptionLabel(), null));

                for (Method method : clazz.getDeclaredMethods()) {
                    VulnerableAppRequestMapping vulnLevel =
                            method.getAnnotation(VulnerableAppRequestMapping.class);

                    if (vulnLevel != null) {
                        VulnerabilityLevelDefinition levelDefinition =
                                new VulnerabilityLevelDefinition();
                        levelDefinition.setLevel(vulnLevel.value());
                        levelDefinition.setVariant(
                                Variant.valueOf(vulnLevel.variant().name()));

                        addFacadeResourceInformation(
                                definition, levelDefinition, vulnLevel.htmlTemplate());

                        for (AttackVector attackVector :
                                method.getAnnotationsByType(AttackVector.class)) {

                            List<VulnerabilityType> types = new ArrayList<>();

                            for (org.sasanlabs.vulnerability.types.VulnerabilityType t :
                                    attackVector.vulnerabilityExposed()) {

                                types.add(new VulnerabilityType("Custom", t.name()));

                                if (t.getCweID() != null) {
                                    types.add(new VulnerabilityType(
                                            "CWE", String.valueOf(t.getCweID())));
                                }
                                if (t.getWascID() != null) {
                                    types.add(new VulnerabilityType(
                                            "WASC", String.valueOf(t.getWascID())));
                                }
                            }

                            levelDefinition.getHints().add(
                                    new VulnerabilityLevelHint(
                                            types,
                                            messageBundle.getString(
                                                    attackVector.description(), null)));
                        }

                        definition.getLevelDescriptionSet().add(levelDefinition);
                    }
                }
                vulnerabilityDefinitions.add(definition);
            }
        }
        return vulnerabilityDefinitions;
    }
    */

    // ======================================================
    // ΝΕΟΣ ΚΩΔΙΚΑΣ – ΔΙΟΡΘΩΣΗ
    // Refactor για μείωση Cognitive Complexity (<15)
    // ======================================================
    @Override
    public List<VulnerabilityDefinition> getVulnerabilityDefinitions()
            throws JsonProcessingException {

        List<VulnerabilityDefinition> vulnerabilityDefinitions = new ArrayList<>();

        Map<String, Object> endpoints =
                envUtils.getAllClassesAnnotatedWithVulnerableAppRestController();

        for (Map.Entry<String, Object> entry : endpoints.entrySet()) {
            Class<?> clazz = entry.getValue().getClass();

            if (!clazz.isAnnotationPresent(VulnerableAppRestController.class)) {
                continue;
            }

            vulnerabilityDefinitions.add(
                    buildVulnerabilityDefinition(entry.getKey(), clazz));
        }

        return vulnerabilityDefinitions;
    }

    // ======================================================
    // ΝΕΑ ΜΕΘΟΔΟΣ (ΔΙΟΡΘΩΣΗ)
    // Δημιουργεί VulnerabilityDefinition
    // ======================================================
    private VulnerabilityDefinition buildVulnerabilityDefinition(
            String name, Class<?> clazz) throws JsonProcessingException {

        VulnerableAppRestController controller =
                clazz.getAnnotation(VulnerableAppRestController.class);

        VulnerabilityDefinition definition = new VulnerabilityDefinition();
        definition.setName(name);
        definition.setId(name);
        definition.setDescription(
                messageBundle.getString(controller.descriptionLabel(), null));

        for (Method method : clazz.getDeclaredMethods()) {
            VulnerableAppRequestMapping vulnLevel =
                    method.getAnnotation(VulnerableAppRequestMapping.class);

            if (vulnLevel != null) {
                definition.getLevelDescriptionSet().add(
                        buildLevelDefinition(definition, method, vulnLevel));
            }
        }
        return definition;
    }

    // ======================================================
    // ΝΕΑ ΜΕΘΟΔΟΣ (ΔΙΟΡΘΩΣΗ)
    // Δημιουργεί VulnerabilityLevelDefinition
    // ======================================================
    private VulnerabilityLevelDefinition buildLevelDefinition(
            VulnerabilityDefinition definition,
            Method method,
            VulnerableAppRequestMapping vulnLevel) {

        VulnerabilityLevelDefinition levelDefinition =
                new VulnerabilityLevelDefinition();

        levelDefinition.setLevel(vulnLevel.value());
        levelDefinition.setVariant(
                Variant.valueOf(vulnLevel.variant().name()));

        addFacadeResourceInformation(
                definition, levelDefinition, vulnLevel.htmlTemplate());

        for (AttackVector attackVector :
                method.getAnnotationsByType(AttackVector.class)) {

            levelDefinition.getHints().add(
                    new VulnerabilityLevelHint(
                            buildVulnerabilityTypes(attackVector),
                            messageBundle.getString(
                                    attackVector.description(), null)));
        }
        return levelDefinition;
    }

    // ======================================================
    // ΝΕΑ ΜΕΘΟΔΟΣ (ΔΙΟΡΘΩΣΗ)
    // Χτίζει VulnerabilityType λίστα
    // ======================================================
    private List<VulnerabilityType> buildVulnerabilityTypes(
            AttackVector attackVector) {

        List<VulnerabilityType> types = new ArrayList<>();

        for (org.sasanlabs.vulnerability.types.VulnerabilityType t :
                attackVector.vulnerabilityExposed()) {

            types.add(new VulnerabilityType("Custom", t.name()));

            if (t.getCweID() != null) {
                types.add(new VulnerabilityType(
                        "CWE", String.valueOf(t.getCweID())));
            }
            if (t.getWascID() != null) {
                types.add(new VulnerabilityType(
                        "WASC", String.valueOf(t.getWascID())));
            }
        }
        return types;
    }

    // ======================================================
    // Χρήση σταθεράς TEMPLATE_BASE_PATH (ΔΙΟΡΘΩΣΗ)
    // ======================================================
    private void addFacadeResourceInformation(
            VulnerabilityDefinition definition,
            VulnerabilityLevelDefinition levelDefinition,
            String template) {

        ResourceInformation resourceInformation = new ResourceInformation();
        levelDefinition.setResourceInformation(resourceInformation);

        resourceInformation.setStaticResources(
                Arrays.asList(
                        new ResourceURI(
                                false,
                                TEMPLATE_BASE_PATH + definition.getName()
                                        + "/" + template + ".css",
                                ResourceType.CSS.name()),
                        new ResourceURI(
                                false,
                                TEMPLATE_BASE_PATH + definition.getName()
                                        + "/" + template + ".js",
                                ResourceType.JAVASCRIPT.name())));

        resourceInformation.setHtmlResource(
                new ResourceURI(
                        false,
                        TEMPLATE_BASE_PATH + definition.getName()
                                + "/" + template + ".html"));
    }
}
