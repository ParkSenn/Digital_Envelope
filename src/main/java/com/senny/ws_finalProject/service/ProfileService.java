package com.senny.ws_finalProject.service;

import com.senny.ws_finalProject.dto.Profile;
import com.senny.ws_finalProject.exceptions.DecryptionException;
import com.senny.ws_finalProject.exceptions.EncryptionException;
import com.senny.ws_finalProject.exceptions.FileReadException;
import com.senny.ws_finalProject.exceptions.SignatureVerificationException;
import com.senny.ws_finalProject.util.AdminDecryptionUtil;
import com.senny.ws_finalProject.util.ProfileEncryptionUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ProfileService {
    private Map<String, String> profileFileMap = new HashMap<>();
    private static final String PROFILE_FILE_EXTENSION = "_profile.dat";

    public void saveProfile(Profile profile) {
        try {
            ProfileEncryptionUtil.saveProfileWithEnvelope(profile, profile.getId());
            profileFileMap.put(profile.getId(), profile.getId() + PROFILE_FILE_EXTENSION);
        } catch (EncryptionException e) {
            e.printStackTrace();
        }
    }


    public List<Profile> getAllProfiles() {
        List<Profile> profiles = new ArrayList<>();

        for (String userId : profileFileMap.keySet()) {
            try {
                Profile profile = AdminDecryptionUtil.decryptProfileEnvelope(userId);
                if (profile != null) {
                    profiles.add(profile);
                }
            } catch (DecryptionException | SignatureVerificationException | FileReadException e) {
                e.printStackTrace();
            }
        }
        return profiles;
    }
}
