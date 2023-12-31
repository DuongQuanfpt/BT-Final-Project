package finalproject.group1.BE.domain.services;

import finalproject.group1.BE.constant.Constants;
import finalproject.group1.BE.domain.entities.User;
import finalproject.group1.BE.domain.enums.DeleteFlag;
import finalproject.group1.BE.domain.enums.Role;
import finalproject.group1.BE.domain.enums.UserStatus;
import finalproject.group1.BE.domain.repository.UserRepository;
import finalproject.group1.BE.web.dto.request.user.UserListRequest;
import finalproject.group1.BE.web.dto.request.user.UserLoginRequest;
import finalproject.group1.BE.web.dto.request.user.UserRegisterRequest;
import finalproject.group1.BE.web.dto.response.user.UserDetailResponse;
import finalproject.group1.BE.web.dto.response.user.UserListResponse;
import finalproject.group1.BE.web.dto.response.user.UserLoginResponse;
import finalproject.group1.BE.web.exception.ExistException;
import finalproject.group1.BE.web.exception.NotFoundException;
import finalproject.group1.BE.web.security.JwtHelper;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeMap;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {

    private UserRepository userRepository;
    private ModelMapper modelMapper;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtHelper jwtHelper;

    public void saveUser(UserRegisterRequest registerRequest) {
        Optional<User> existUser = userRepository.findByEmail(registerRequest.getLoginId());
        if (existUser.isPresent()) {
            if (existUser.get().getStatus() == UserStatus.LOCKED) {
                throw new ExistException();
            }
            throw new ExistException();
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(Constants.VALID_DATE_FORMAT);

        TypeMap<UserRegisterRequest, User> propertyMapper = modelMapper.createTypeMap(UserRegisterRequest.class, User.class);
        propertyMapper.addMappings(mapper -> mapper.skip(User::setId)); //skip map for id
        propertyMapper.addMapping(UserRegisterRequest::getLoginId, User::setEmail);//map loginId to email

        User newUser = modelMapper.map(registerRequest, User.class);

        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setBirthDay(LocalDate.parse(registerRequest.getBirthDay(), formatter));
        newUser.setDeleteFlag(DeleteFlag.NORMAL);
        newUser.setStatus(UserStatus.NORMAL);
        newUser.setRole(Role.ROLE_USER);

        userRepository.save(newUser);
    }

    public UserLoginResponse authenticate(UserLoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getLoginId(), loginRequest.getPassword()));

        User user = (User) authentication.getPrincipal();
        user = userRepository.findByEmail(user.getEmail()).get();

        String token = jwtHelper.createToken(user);
        return new UserLoginResponse(token);
    }

    public List<UserListResponse> getUserList(UserListRequest listRequest, Pageable pageable) {

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(Constants.VALID_DATE_FORMAT);

        String username = null;
        String email = null;
        LocalDate startDate = null;
        LocalDate endDate = null;
        Float totalPrice = null;

        if (listRequest.getUserName() != null && !listRequest.getUserName().isEmpty()) {
            username = listRequest.getUserName();
        }

        if (listRequest.getLoginId() != null && !listRequest.getLoginId().isEmpty()) {
            email = listRequest.getLoginId();
        }

        if (listRequest.getStartBirthDay() != null && !listRequest.getStartBirthDay().isEmpty()) {
            startDate = LocalDate.parse(listRequest.getStartBirthDay(), formatter);
        }

        if (listRequest.getEndBirthDay() != null && !listRequest.getEndBirthDay().isEmpty()) {
            endDate = LocalDate.parse(listRequest.getEndBirthDay(), formatter);
        }

        if (listRequest.getTotalPrice() != null) {
            totalPrice = listRequest.getTotalPrice();
        }

        return userRepository.findUserBySearchConditions(username, email,
                startDate, endDate, totalPrice, pageable);
    }

    public UserDetailResponse getUserDetails(int id) {
        User user = userRepository.findById(id).orElseThrow(() -> new NotFoundException());

        TypeMap<User, UserDetailResponse> propertyMapper = modelMapper.createTypeMap(User.class, UserDetailResponse.class);
        propertyMapper.addMapping(User::getEmail, UserDetailResponse::setLoginId);//map loginId to email

        return modelMapper.map(user, UserDetailResponse.class);
    }
}
