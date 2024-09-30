package org.chzz.market.domain.user.service;

import static org.chzz.market.domain.user.error.UserErrorCode.NICKNAME_DUPLICATION;
import static org.chzz.market.domain.user.error.UserErrorCode.USER_NOT_FOUND;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chzz.market.domain.auction.error.AuctionErrorCode;
import org.chzz.market.domain.auction.error.AuctionException;
import org.chzz.market.domain.auction.repository.AuctionRepository;
import org.chzz.market.domain.product.repository.ProductRepository;
import org.chzz.market.domain.user.dto.response.UpdateProfileResponse;
import org.chzz.market.domain.user.dto.request.UpdateUserProfileRequest;
import org.chzz.market.domain.user.dto.request.UserCreateRequest;
import org.chzz.market.domain.user.dto.response.NicknameAvailabilityResponse;
import org.chzz.market.domain.user.dto.response.ParticipationCountsResponse;
import org.chzz.market.domain.user.dto.response.UserProfileResponse;
import org.chzz.market.domain.user.entity.User;
import org.chzz.market.domain.user.error.exception.UserException;
import org.chzz.market.domain.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {
    private final UserRepository userRepository;
    private final AuctionRepository auctionRepository;
    private final ProductRepository productRepository;

    /**
     * 사용자 등록
     *
     * @param userCreateRequest 사용자 생성 요청
     * @return 사용자 엔티티
     */
    @Transactional
    public User completeUserRegistration(Long userId, UserCreateRequest userCreateRequest) {
        User user = userRepository.findById(userId).orElseThrow(() -> new UserException(USER_NOT_FOUND));
        userRepository.findByNickname(userCreateRequest.getNickname()).ifPresent(user1 -> {
            throw new UserException(NICKNAME_DUPLICATION);
        });
        user.createUser(userCreateRequest);
        user.addBankAccount(userCreateRequest.toBankAccount());
        return user;
    }

    /**
     * 사용자 프로필 조회 (닉네임 기반)
     *
     * @param nickname 닉네임
     * @return 사용자 프로필 응답
     */
    public UserProfileResponse getUserProfileByNickname(String nickname) {
        return getUserProfileInternal(findUserByNickname(nickname));
    }

    /**
     * 사용자 프로필 조회 (유저 ID 기반)
     * @param userId 유저 ID
     * @return 사용자 프로필 응답
     */
    public UserProfileResponse getUserProfileById(Long userId) {
        return getUserProfileInternal(findUserById(userId));
    }

    public NicknameAvailabilityResponse checkNickname(String nickname) {
        return new NicknameAvailabilityResponse(userRepository.findByNickname(nickname).isEmpty());
    }

    /**
     * 내 프로필 수정
     *
     * @param userId 유저 ID
     * @param request 프로필 수정 요청
     * @return 프로필 수정 응답
     */
    @Transactional
    public UpdateProfileResponse updateUserProfile(Long userId, UpdateUserProfileRequest request) {
        // 유저 유효성 검사
        User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new UserException(USER_NOT_FOUND));
        userRepository.findByNickname(request.getNickname()).ifPresent(user -> {
            if(!existingUser.equals(user)) { // 본인 닉네일시
                throw new UserException(NICKNAME_DUPLICATION);
            }
        });

        // 프로필 정보 업데이트
        existingUser.updateProfile(
                request.getNickname(),
                request.getBio(),
                request.getLink()
        );
        return UpdateProfileResponse.from(existingUser);
    }

    public String getCustomerKey(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserException(USER_NOT_FOUND))
                .getCustomerKey().toString();
    }

    /*
     * 내 프로필 조회
     */
    private UserProfileResponse getUserProfileInternal(User user) {
        //TODO 2024 09 23 16:21:01 : 애플리케이션 레벨 연산이 아닌 조회 쿼리로 갯수 작성
        /*
            참여한 경매 내역
            1. 진행중인 경매: 사용자의 입찰 기록을 통해 경매를 확인, 그중 진행중인거만 count
            2. 성공한 경매: 경매중 winnerId가 사용자의 pk인 경우를 count
            3. 실패한 경매: 사용자의 입찰 기록을 통해 경매를 확인, 그중 종료된것 중
         */
        long preRegisterCount = productRepository.countPreRegisteredProductsByUserId(user.getId());
        long registeredAuctionCount = auctionRepository.countByProductUserId(user.getId());

        ParticipationCountsResponse counts = auctionRepository.getParticipationCounts(user.getId())
                .orElseThrow(() -> new AuctionException(AuctionErrorCode.CONFLICT));

        return UserProfileResponse.of(user, counts, preRegisterCount, registeredAuctionCount);
    }

    /*
     * 닉네임으로 사용자 조회
     */
    private User findUserByNickname(String nickname) {
        return userRepository.findByNickname(nickname)
                .orElseThrow(() -> new UserException(USER_NOT_FOUND));
    }

    /*
     * ID로 사용자 조회
     */
    private User findUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserException(USER_NOT_FOUND));
    }
}
