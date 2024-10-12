package org.chzz.market.domain.product.service;

import static org.chzz.market.domain.image.error.ImageErrorCode.INVALID_IMAGE_COUNT;
import static org.chzz.market.domain.image.error.ImageErrorCode.MAX_IMAGE_COUNT_EXCEEDED;
import static org.chzz.market.domain.notification.entity.NotificationType.PRE_AUCTION_CANCELED;
import static org.chzz.market.domain.product.error.ProductErrorCode.ALREADY_IN_AUCTION;
import static org.chzz.market.domain.product.error.ProductErrorCode.FORBIDDEN_PRODUCT_ACCESS;
import static org.chzz.market.domain.product.error.ProductErrorCode.PRODUCT_ALREADY_AUCTIONED;
import static org.chzz.market.domain.product.error.ProductErrorCode.PRODUCT_NOT_FOUND;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.chzz.market.domain.auction.repository.AuctionRepository;
import org.chzz.market.domain.image.entity.Image;
import org.chzz.market.domain.image.service.ImageService;
import org.chzz.market.domain.notification.event.NotificationEvent;
import org.chzz.market.domain.product.dto.CategoryResponse;
import org.chzz.market.domain.product.dto.DeleteProductResponse;
import org.chzz.market.domain.product.dto.ProductDetailsResponse;
import org.chzz.market.domain.product.dto.ProductResponse;
import org.chzz.market.domain.product.dto.UpdateProductRequest;
import org.chzz.market.domain.product.dto.UpdateProductResponse;
import org.chzz.market.domain.product.entity.Product;
import org.chzz.market.domain.product.entity.Product.Category;
import org.chzz.market.domain.product.error.ProductException;
import org.chzz.market.domain.product.repository.ProductRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ProductService {
    private final ImageService imageService;
    private final ProductRepository productRepository;
    private final AuctionRepository auctionRepository;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * 사전 등록 상품 목록 조회
     */
    public Page<ProductResponse> getProductListByCategory(Category category, Long userId, Pageable pageable) {
        return productRepository.findProductsByCategory(category, userId, pageable);
    }

    /**
     * 상품 상세 정보 조회
     */
    public ProductDetailsResponse getProductDetails(Long productId, Long userId) {
        return productRepository.findProductDetailsById(productId, userId)
                .orElseThrow(() -> new ProductException(PRODUCT_NOT_FOUND));
    }

    /**
     * 나의 사전 등록 상품 목록 조회
     */
    public Page<ProductResponse> getProductListByNickname(String nickname, Pageable pageable) {
        return productRepository.findProductsByNickname(nickname, pageable);
    }

    public Page<ProductResponse> getProductListByUserId(Long userId, Pageable pageable) {
        return productRepository.findProductsByUserId(userId, pageable);
    }

    /**
     * 내가 참여한 사전경매 조회
     */
    public Page<ProductResponse> getLikedProductList(Long userId, Pageable pageable) {
        return productRepository.findLikedProductsByUserId(userId, pageable);
    }

    /**
     * 상품 카테고리 목록 조회
     */
    public List<CategoryResponse> getCategories() {
        return Arrays.stream(Category.values())
                .map(category -> new CategoryResponse(category.name(), category.getDisplayName()))
                .toList();
    }

    /**
     * 사전 등록 상품 수정
     */
    @Transactional
    public UpdateProductResponse updateProduct(Long userId, Long productId, UpdateProductRequest request,
                                               Map<String, MultipartFile> newImages) {
        // 상품 유효성 검사
        Product existingProduct = productRepository.findProductByIdWithImage(productId)
                .orElseThrow(() -> new ProductException(PRODUCT_NOT_FOUND));

        if (!existingProduct.isOwner(userId)) {
            throw new ProductException(FORBIDDEN_PRODUCT_ACCESS);
        }

        // 경매 등록 상태 유무 유효성 검사
        if (auctionRepository.existsByProductId(productId)) {
            throw new ProductException(ALREADY_IN_AUCTION);
        }

        // 상품 정보 업데이트
        existingProduct.update(request);

        // 이미지 저장
        updateProductImages(existingProduct, request, newImages);

        log.info("상품 ID {}번에 대한 사전 등록 정보를 업데이트를 완료했습니다.", productId);
        return UpdateProductResponse.from(existingProduct);
    }

    /**
     * 사전 등록 상품 삭제
     */
    @Retryable(
            retryFor = {TransientDataAccessException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 1000)
    )
    @Transactional
    public DeleteProductResponse deleteProduct(Long productId, Long userId) {
        log.info("상품 ID {}번에 해당하는 상품 삭제 프로세스를 시작합니다.", productId);

        // 상품 유효성 검사
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> {
                    log.info("상품 ID {}번에 해당하는 상품을 찾을 수 없습니다.", productId);
                    return new ProductException(PRODUCT_NOT_FOUND);
                });

        if (!product.isOwner(userId)) {
            throw new ProductException(FORBIDDEN_PRODUCT_ACCESS);
        }

        // 경매 등록 여부 확인
        if (auctionRepository.existsByProductId(productId)) {
            log.info("상품 ID {}번은 이미 경매로 등록되어 삭제할 수 없습니다.", productId);
            throw new ProductException(PRODUCT_ALREADY_AUCTIONED);
        }

        deleteProductImages(product);
        productRepository.delete(product);

        // 좋아요 누른 사용자 ID 추출
        List<Long> likedUserIds = product.getLikes().stream()
                .map(like -> like.getUser().getId())
                .distinct()
                .toList();
        if (!likedUserIds.isEmpty()) {
            eventPublisher.publishEvent(
                    NotificationEvent.createSimpleNotification(likedUserIds, PRE_AUCTION_CANCELED,
                            PRE_AUCTION_CANCELED.getMessage(product.getName()),
                            null)); // TODO: 사전 등록 취소 (soft delete 로 변경시 이미지 추가)
        }

        log.info("사전 등록 상품 ID{}번에 해당하는 상품을 성공적으로 삭제하였습니다. (좋아요 누른 사용자 수: {})", productId, likedUserIds.size());

        return DeleteProductResponse.ofPreRegistered(product, likedUserIds.size());
    }

    /**
     * 상품 이미지 업데이트
     */
    private void updateProductImages(Product product,
                                     UpdateProductRequest request,
                                     Map<String, MultipartFile> images) {
        Map<String, MultipartFile> newImages = removeRequestKey(images);
        Map<Long, Integer> imageSequence = Optional.ofNullable(request.getImageSequence())
                .orElse(Collections.emptyMap());

        // 요청에 대한 총 이미지 수 검증
        validateTotalImageCount(imageSequence.size() + newImages.size());

        // 기존 이미지 처리 (업데이트할 이미지와 삭제할 이미지 구분)
        processExistingImages(product, imageSequence);

        // 새 이미지가 있는 경우
        if (!newImages.isEmpty()) {
            uploadAndAddNewImages(product, newImages);
        }
        product.validateImageSize();
    }

    /**
     * 상품 이미지 삭제
     */
    private void deleteProductImages(Product product) {
        List<String> imageUrls = product.getImages().stream()
                .map(Image::getCdnPath)
                .toList();

        imageService.deleteUploadImages(imageUrls);
        log.info("상품 ID {}번에 해당하는 상품의 이미지를 모두 삭제하였습니다.", product.getId());
    }

    /**
     * 새로운 이미지 맵에서 "request" 키를 제거하고, null 값을 처리 (@RequestPart 사용으로 인한)
     */
    private Map<String, MultipartFile> removeRequestKey(Map<String, MultipartFile> newImages) {
        if (newImages != null) {
            newImages.remove("request");
        }
        return newImages != null ? newImages : Collections.emptyMap();
    }

    /**
     * 총 이미지 수(기존 이미지 갯수 + 새롭게 업로드할 이미지 갯수) 가 유효한지 검증합니다.
     */
    private void validateTotalImageCount(int totalSize) {
        if (totalSize > 5) {
            throw new ProductException(MAX_IMAGE_COUNT_EXCEEDED);
        } else if (totalSize == 0) {
            throw new ProductException(INVALID_IMAGE_COUNT);
        }
    }

    /**
     * 기존 이미지 업데이트 및 삭제 처리
     */
    private void processExistingImages(Product product, Map<Long, Integer> imageSequence) {
        List<Image> imagesToUpdate = new ArrayList<>();
        List<Image> imagesToRemove = new ArrayList<>();

        product.getImages().forEach(image -> {
            if (imageSequence.containsKey(image.getId())) {
                imagesToUpdate.add(image); // 업데이트할 이미지
            } else {
                imagesToRemove.add(image); // 삭제할 이미지
            }
        });
        product.removeImages(imagesToRemove); // 삭제할 이미지 처리
        imageService.updateImageSequences(imagesToUpdate, imageSequence); // 시퀀스 업데이트할 이미지 처리
    }

    /**
     * 상품 수정 시 새로운 이미지 업로드
     */
    private void uploadAndAddNewImages(Product product, Map<String, MultipartFile> newImages) {
        List<Image> newImageEntities = imageService.uploadSequentialImages(product, newImages);
        product.addImages(newImageEntities);
        log.info("상품 ID {}번의 새 이미지를 성공적으로 저장하였습니다.", product.getId());
    }
}
