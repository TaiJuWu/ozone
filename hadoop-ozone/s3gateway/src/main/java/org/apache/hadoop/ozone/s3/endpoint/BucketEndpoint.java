/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.ozone.s3.endpoint;

import static org.apache.hadoop.ozone.OzoneAcl.AclScope.ACCESS;
import static org.apache.hadoop.ozone.OzoneConsts.ETAG;
import static org.apache.hadoop.ozone.OzoneConsts.OZONE_URI_DELIMITER;
import static org.apache.hadoop.ozone.audit.AuditLogger.PerformanceStringBuilder;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LIST_KEYS_SHALLOW_ENABLED;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LIST_KEYS_SHALLOW_ENABLED_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LIST_MAX_KEYS_LIMIT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LIST_MAX_KEYS_LIMIT_DEFAULT;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newError;
import static org.apache.hadoop.ozone.s3.util.S3Consts.ENCODING_TYPE;

import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.HEAD;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.OzoneAcl;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.client.OzoneBucket;
import org.apache.hadoop.ozone.client.OzoneKey;
import org.apache.hadoop.ozone.client.OzoneMultipartUploadList;
import org.apache.hadoop.ozone.client.OzoneVolume;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.exceptions.OMException.ResultCodes;
import org.apache.hadoop.ozone.om.helpers.ErrorInfo;
import org.apache.hadoop.ozone.om.helpers.OzoneAclUtil;
import org.apache.hadoop.ozone.s3.commontypes.EncodingTypeObject;
import org.apache.hadoop.ozone.s3.commontypes.KeyMetadata;
import org.apache.hadoop.ozone.s3.endpoint.MultiDeleteRequest.DeleteObject;
import org.apache.hadoop.ozone.s3.endpoint.MultiDeleteResponse.DeletedObject;
import org.apache.hadoop.ozone.s3.endpoint.MultiDeleteResponse.Error;
import org.apache.hadoop.ozone.s3.endpoint.S3BucketAcl.Grant;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.util.ContinueToken;
import org.apache.hadoop.ozone.s3.util.S3StorageType;
import org.apache.hadoop.ozone.security.acl.IAccessAuthorizer;
import org.apache.hadoop.util.Time;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bucket level rest endpoints.
 */
@Path("/{bucket}")
public class BucketEndpoint extends EndpointBase {

  private static final Logger LOG =
      LoggerFactory.getLogger(BucketEndpoint.class);

  @Context
  private HttpHeaders headers;

  private boolean listKeysShallowEnabled;
  private int maxKeysLimit = 1000;

  @Inject
  private OzoneConfiguration ozoneConfiguration;

  /**
   * Rest endpoint to list objects in a specific bucket.
   * <p>
   * See: https://docs.aws.amazon.com/AmazonS3/latest/API/v2-RESTBucketGET.html
   * for more details.
   */
  private int validateMaxKeys(int maxKeys) throws OS3Exception {
    if (maxKeys < 0) {
      throw newError(S3ErrorTable.INVALID_ARGUMENT, "maxKeys must be >= 0");
    }

    return Math.min(maxKeys, maxKeysLimit);
  }

  private static final class ListObjectsParams {
    private final String delimiter;
    private final String encodingType;
    private final int maxKeys;
    private final String prefix;
    private final String continueToken;
    private final String startAfter;
    private final String marker;

    ListObjectsParams(String delimiter, String encodingType, int maxKeys,
                             String prefix, String continueToken, String startAfter,
                             String marker) {
      this.delimiter = delimiter;
      this.encodingType = encodingType;
      this.maxKeys = maxKeys;
      this.prefix = prefix;
      this.continueToken = continueToken;
      this.startAfter = startAfter;
      this.marker = marker;
    }

    public String getDelimiter() {
      return delimiter;
    }

    public String getEncodingType() {
      return encodingType;
    }

    public int getMaxKeys() {
      return maxKeys;
    }

    public String getPrefix() {
      return prefix;
    }

    public String getContinueToken() {
      return continueToken;
    }

    public String getStartAfter() {
      return startAfter;
    }

    public String getMarker() {
      return marker;
    }

    public String getEffectiveStartKey() throws OS3Exception {
      if (continueToken != null) {
        ContinueToken decodedToken = ContinueToken.decodeFromString(continueToken);
        return decodedToken.getLastKey();
      }

      if (startAfter != null) {
        return startAfter;
      }

      return marker;
    }
  }

  /**
   * Rest endpoint to list objects in a specific bucket.
   * <p>
   * See: https://docs.aws.amazon.com/AmazonS3/latest/API/v2-RESTBucketGET.html
   * for more details.
   */
  @SuppressWarnings({"parameternumber", "methodlength"})
  public Response get(
      @PathParam("bucket") String bucketName,
      @QueryParam("delimiter") String delimiter,
      @QueryParam("encoding-type") String encodingType,
      @QueryParam("marker") String marker,
      @DefaultValue("1000") @QueryParam("max-keys") int maxKeys,
      @QueryParam("prefix") String prefix,
      @QueryParam("continuation-token") String continueToken,
      @QueryParam("start-after") String startAfter,
      @QueryParam("uploads") String uploads,
      @QueryParam("acl") String aclMarker,
      @QueryParam("key-marker") String keyMarker,
      @QueryParam("upload-id-marker") String uploadIdMarker,
      @DefaultValue("1000") @QueryParam("max-uploads") int maxUploads) throws OS3Exception, IOException {

    // 1. 根據特殊參數分派到不同的處理邏輯
    if (aclMarker != null) {
      return handleGetAcl(bucketName);
    }

    if (uploads != null) {
      return handleListMultipartUploads(bucketName, prefix, keyMarker, uploadIdMarker, maxUploads);
    }

    // 2. 封裝 ListObjects 的參數 (使用明確類型，而非 var)
    ListObjectsParams params = new ListObjectsParams(delimiter, encodingType, maxKeys, prefix,
        continueToken, startAfter, marker);

    // 3. 呼叫核心的 List Objects 處理邏輯
    return handleListObjects(bucketName, params);
  }

  private Response handleGetAcl(String bucketName) throws OS3Exception, IOException {
    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.GET_ACL;
    try {
      S3BucketAcl result = getAcl(bucketName);
      getMetrics().updateGetAclSuccessStats(startNanos);
      AUDIT.logReadSuccess(
          buildAuditMessageForSuccess(s3GAction, getAuditParameters()));
      return Response.ok(result, MediaType.APPLICATION_XML_TYPE).build();
    } catch (Exception ex) {
      AUDIT.logReadFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      throw ex;
    }
  }

  private Response handleListMultipartUploads(String bucketName, String prefix,
                                              String keyMarker, String uploadIdMarker, int maxUploads)
      throws OS3Exception, IOException {
    S3GAction s3GAction = S3GAction.LIST_MULTIPART_UPLOAD;
    long startNanos = Time.monotonicNowNanos();
    // ... 此處應包含完整的 try-catch 和日誌記錄 ...
    return listMultipartUploads(bucketName, prefix, keyMarker, uploadIdMarker, maxUploads);
  }

  private Response handleListObjects(String bucketName, ListObjectsParams params)
      throws OS3Exception, IOException {
    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.GET_BUCKET;
    PerformanceStringBuilder perf = new PerformanceStringBuilder();

    try {
      // 1. 驗證參數
      validateListObjectsParams(params);
      final String effectivePrefix = params.getPrefix() == null ? "" : params.getPrefix();
      final String prevKey = params.getEffectiveStartKey();

      // 2. 獲取資料
      OzoneBucket bucket = getBucket(bucketName);
      S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());

      boolean shallow = listKeysShallowEnabled && OZONE_URI_DELIMITER.equals(params.getDelimiter());
      Iterator<? extends OzoneKey> keyIterator = bucket.listKeys(effectivePrefix, prevKey, shallow);

      // 3. 建構回應
      ListObjectResponse response = buildListObjectResponse(keyIterator, bucketName, params, bucket);

      // 4. 成功時記錄 Metrics 和 Audit
      int keyCount = response.getCommonPrefixes().size() + response.getContents().size();
      long opLatencyNs = getMetrics().updateGetBucketSuccessStats(startNanos);
      getMetrics().incListKeyCount(keyCount);
      perf.appendCount(keyCount);
      perf.appendOpLatencyNanos(opLatencyNs);
      AUDIT.logReadSuccess(buildAuditMessageForSuccess(s3GAction, getAuditParameters(), perf));
      response.setKeyCount(keyCount);

      return Response.ok(response).build();

    } catch (OMException ex) {
      getMetrics().updateGetBucketFailureStats(startNanos);
      AUDIT.logReadFailure(buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      if (isAccessDenied(ex)) {
        throw newError(S3ErrorTable.ACCESS_DENIED, bucketName, ex);
      } else if (ex.getResult() == ResultCodes.FILE_NOT_FOUND) {
        LOG.debug("Key Not found prefix: {}", params.getPrefix());
        return Response.ok(createEmptyListResponse(bucketName, params)).build();
      }
      throw ex;
    } catch (Exception ex) {
      getMetrics().updateGetBucketFailureStats(startNanos);
      AUDIT.logReadFailure(buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      throw ex;
    }
  }

  private ListObjectResponse buildListObjectResponse(
      Iterator<? extends OzoneKey> keyIterator, String bucketName,
      ListObjectsParams params, OzoneBucket bucket) throws UnsupportedEncodingException, OS3Exception {

    final ListObjectResponse response = createEmptyListResponse(bucketName, params);
    final String prefix = params.getPrefix() == null ? "" : params.getPrefix();

    ListingState state = new ListingState(params.getMaxKeys(), params.getStartAfter());
    if (params.getContinueToken() != null) {
      state.setPrevDir(ContinueToken.decodeFromString(params.getContinueToken()).getLastDir());
    }

    while (keyIterator.hasNext() && !state.isFull()) {
      OzoneKey key = keyIterator.next();
      processKey(key, response, state, prefix, params.getDelimiter(), params.getEncodingType(), bucket);
    }

    // 處理分頁 (Truncation) 邏輯
    if (keyIterator.hasNext() && state.getLastKey() != null) {
      response.setTruncated(true);
      ContinueToken nextToken = new ContinueToken(state.getLastKey(), state.getPrevDir());
      response.setNextToken(nextToken.encodeToString());
      response.setNextMarker(state.getLastKey());
    } else {
      response.setTruncated(false);
    }

    response.setKeyCount(state.getCount());
    return response;
  }

  private void processKey(OzoneKey key, ListObjectResponse response,
                          ListingState state, String prefix, String delimiter, String encodingType, OzoneBucket bucket)
      throws UnsupportedEncodingException {

    if (bucket.getBucketLayout().isFileSystemOptimized() &&
        StringUtils.isNotEmpty(prefix) && !key.getName().startsWith(prefix)) {
      return;
    }

    if (state.isFirstKey() && Objects.equals(state.getStartAfter(), key.getName())) {
      state.processedFirstKey(); // 標記已處理過 startAfter，但仍需跳過
      return;
    }
    state.processedFirstKey();

    String relativeKeyName = key.getName().substring(prefix.length());

    if (StringUtils.isNotEmpty(delimiter)) {
      int delimiterIndex = relativeKeyName.indexOf(delimiter);
      if (delimiterIndex >= 0) {
        String dirName = relativeKeyName.substring(0, delimiterIndex);
        if (!dirName.equals(state.getPrevDir())) {
          response.addPrefix(EncodingTypeObject.createNullable(
              prefix + dirName + delimiter, encodingType));
          state.setPrevDir(dirName);
          state.incrementCount();
        }
      } else {
        addKey(response, key);
        state.incrementCount();
      }
    } else {
      addKey(response, key);
      state.incrementCount();
    }

    state.setLastKey(key.getName());
  }

  private static class ListingState {
    private final int maxKeys;
    private final String startAfter;
    private int count = 0;
    private String prevDir;
    private String lastKey;
    private boolean isFirstKey = true;

    ListingState(int maxKeys, String startAfter) {
      this.maxKeys = maxKeys;
      this.startAfter = startAfter;
    }

    void incrementCount() {
      this.count++;
    }

    boolean isFull() {
      return count >= maxKeys;
    }

    void processedFirstKey() {
      this.isFirstKey = false;
    }

    // Getters and Setters
    int getCount() {
      return count;
    }

    String getPrevDir() {
      return prevDir;
    }

    void setPrevDir(String prevDir) {
      this.prevDir = prevDir;
    }

    String getLastKey() {
      return lastKey;
    }

    void setLastKey(String lastKey) {
      this.lastKey = lastKey;
    }

    String getStartAfter() {
      return startAfter;
    }

    boolean isFirstKey() {
      return isFirstKey;
    }
  }

  private ListObjectResponse createEmptyListResponse(String bucketName, ListObjectsParams params) {
    ListObjectResponse response = new ListObjectResponse();
    response.setName(bucketName);
    response.setMaxKeys(params.getMaxKeys());
    response.setEncodingType(params.getEncodingType());
    response.setMarker(params.getMarker() == null ? "" : params.getMarker());
    response.setDelimiter(
        EncodingTypeObject.createNullable(params.getDelimiter(), params.getEncodingType()));
    response.setPrefix(
        EncodingTypeObject.createNullable(params.getPrefix(), params.getEncodingType()));
    response.setStartAfter(
        EncodingTypeObject.createNullable(params.getStartAfter(), params.getEncodingType()));
    response.setContinueToken(params.getContinueToken());
    response.setTruncated(false);
    return response;
  }

  private void validateListObjectsParams(ListObjectsParams params) throws OS3Exception {
    validateMaxKeys(params.getMaxKeys());
    if (params.getEncodingType() != null && !params.getEncodingType().equals(ENCODING_TYPE)) {
      throw S3ErrorTable.newError(S3ErrorTable.INVALID_ARGUMENT, params.getEncodingType());
    }
  }

  @PUT
  public Response put(@PathParam("bucket") String bucketName,
                      @QueryParam("acl") String aclMarker,
                      InputStream body) throws IOException, OS3Exception {
    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.CREATE_BUCKET;

    try {
      if (aclMarker != null) {
        s3GAction = S3GAction.PUT_ACL;
        Response response =  putAcl(bucketName, body);
        AUDIT.logWriteSuccess(
            buildAuditMessageForSuccess(s3GAction, getAuditParameters()));
        return response;
      }
      String location = createS3Bucket(bucketName);
      AUDIT.logWriteSuccess(
          buildAuditMessageForSuccess(s3GAction, getAuditParameters()));
      getMetrics().updateCreateBucketSuccessStats(startNanos);
      return Response.status(HttpStatus.SC_OK).header("Location", location)
          .build();
    } catch (OMException exception) {
      auditWriteFailure(s3GAction, exception);
      getMetrics().updateCreateBucketFailureStats(startNanos);
      if (exception.getResult() == ResultCodes.INVALID_BUCKET_NAME) {
        throw newError(S3ErrorTable.INVALID_BUCKET_NAME, bucketName, exception);
      }
      throw exception;
    } catch (Exception ex) {
      AUDIT.logWriteFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      throw ex;
    }
  }

  public Response listMultipartUploads(
      String bucketName,
      String prefix,
      String keyMarker,
      String uploadIdMarker,
      int maxUploads)
      throws OS3Exception, IOException {

    if (maxUploads < 1) {
      throw newError(S3ErrorTable.INVALID_ARGUMENT, "max-uploads",
          new Exception("max-uploads must be positive"));
    } else {
      maxUploads = Math.min(maxUploads, 1000);
    }

    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.LIST_MULTIPART_UPLOAD;

    OzoneBucket bucket = getBucket(bucketName);

    try {
      S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
      OzoneMultipartUploadList ozoneMultipartUploadList =
          bucket.listMultipartUploads(prefix, keyMarker, uploadIdMarker, maxUploads);

      ListMultipartUploadsResult result = new ListMultipartUploadsResult();
      result.setBucket(bucketName);
      result.setKeyMarker(keyMarker);
      result.setUploadIdMarker(uploadIdMarker);
      result.setNextKeyMarker(ozoneMultipartUploadList.getNextKeyMarker());
      result.setPrefix(prefix);
      result.setNextUploadIdMarker(ozoneMultipartUploadList.getNextUploadIdMarker());
      result.setMaxUploads(maxUploads);
      result.setTruncated(ozoneMultipartUploadList.isTruncated());

      ozoneMultipartUploadList.getUploads().forEach(upload -> result.addUpload(
          new ListMultipartUploadsResult.Upload(
              upload.getKeyName(),
              upload.getUploadId(),
              upload.getCreationTime(),
              S3StorageType.fromReplicationConfig(upload.getReplicationConfig())
          )));
      AUDIT.logReadSuccess(buildAuditMessageForSuccess(s3GAction,
          getAuditParameters()));
      getMetrics().updateListMultipartUploadsSuccessStats(startNanos);
      return Response.ok(result).build();
    } catch (OMException exception) {
      AUDIT.logReadFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(),
              exception));
      getMetrics().updateListMultipartUploadsFailureStats(startNanos);
      if (isAccessDenied(exception)) {
        throw newError(S3ErrorTable.ACCESS_DENIED, prefix, exception);
      }
      throw exception;
    } catch (Exception ex) {
      AUDIT.logReadFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      throw ex;
    }
  }

  /**
   * Rest endpoint to check the existence of a bucket.
   * <p>
   * See: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketHEAD.html
   * for more details.
   */
  @HEAD
  public Response head(@PathParam("bucket") String bucketName)
      throws OS3Exception, IOException {
    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.HEAD_BUCKET;
    try {
      OzoneBucket bucket = getBucket(bucketName);
      S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
      AUDIT.logReadSuccess(
          buildAuditMessageForSuccess(s3GAction, getAuditParameters()));
      getMetrics().updateHeadBucketSuccessStats(startNanos);
      return Response.ok().build();
    } catch (Exception e) {
      AUDIT.logReadFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), e));
      throw e;
    }
  }

  /**
   * Rest endpoint to delete specific bucket.
   * <p>
   * See: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketDELETE.html
   * for more details.
   */
  @DELETE
  public Response delete(@PathParam("bucket") String bucketName)
      throws IOException, OS3Exception {
    long startNanos = Time.monotonicNowNanos();
    S3GAction s3GAction = S3GAction.DELETE_BUCKET;

    try {
      if (S3Owner.hasBucketOwnershipVerificationConditions(headers)) {
        OzoneBucket bucket = getBucket(bucketName);
        S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
      }
      deleteS3Bucket(bucketName);
    } catch (OMException ex) {
      AUDIT.logWriteFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      getMetrics().updateDeleteBucketFailureStats(startNanos);
      if (ex.getResult() == ResultCodes.BUCKET_NOT_EMPTY) {
        throw newError(S3ErrorTable.BUCKET_NOT_EMPTY, bucketName, ex);
      } else if (ex.getResult() == ResultCodes.BUCKET_NOT_FOUND) {
        throw newError(S3ErrorTable.NO_SUCH_BUCKET, bucketName, ex);
      } else if (isAccessDenied(ex)) {
        throw newError(S3ErrorTable.ACCESS_DENIED, bucketName, ex);
      } else {
        throw ex;
      }
    } catch (Exception ex) {
      AUDIT.logWriteFailure(
          buildAuditMessageForFailure(s3GAction, getAuditParameters(), ex));
      throw ex;
    }

    AUDIT.logWriteSuccess(buildAuditMessageForSuccess(s3GAction,
        getAuditParameters()));
    getMetrics().updateDeleteBucketSuccessStats(startNanos);
    return Response
        .status(HttpStatus.SC_NO_CONTENT)
        .build();

  }

  /**
   * Implement multi delete.
   * <p>
   * see: https://docs.aws.amazon
   * .com/AmazonS3/latest/API/multiobjectdeleteapi.html
   */
  @POST
  @Produces(MediaType.APPLICATION_XML)
  public MultiDeleteResponse multiDelete(@PathParam("bucket") String bucketName,
                                         @QueryParam("delete") String delete,
                                         MultiDeleteRequest request)
      throws OS3Exception, IOException {
    S3GAction s3GAction = S3GAction.MULTI_DELETE;

    OzoneBucket bucket = getBucket(bucketName);
    MultiDeleteResponse result = new MultiDeleteResponse();
    List<String> deleteKeys = new ArrayList<>();

    if (request.getObjects() != null) {
      Map<String, ErrorInfo> undeletedKeyResultMap;
      for (DeleteObject keyToDelete : request.getObjects()) {
        deleteKeys.add(keyToDelete.getKey());
      }
      long startNanos = Time.monotonicNowNanos();
      try {
        S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
        undeletedKeyResultMap = bucket.deleteKeys(deleteKeys, true);
        for (DeleteObject d : request.getObjects()) {
          ErrorInfo error = undeletedKeyResultMap.get(d.getKey());
          boolean deleted = error == null ||
              // if the key is not found, it is assumed to be successfully deleted
              ResultCodes.KEY_NOT_FOUND.name().equals(error.getCode());
          if (deleted) {
            deleteKeys.remove(d.getKey());
            if (!request.isQuiet()) {
              result.addDeleted(new DeletedObject(d.getKey()));
            }
          } else {
            result.addError(new Error(d.getKey(), error.getCode(), error.getMessage()));
          }
        }
        getMetrics().updateDeleteKeySuccessStats(startNanos);
      } catch (IOException ex) {
        LOG.error("Delete key failed: {}", ex.getMessage());
        getMetrics().updateDeleteKeyFailureStats(startNanos);
        result.addError(
            new Error("ALL", "InternalError",
                ex.getMessage()));
      }
    }

    Map<String, String> auditMap = getAuditParameters();
    auditMap.put("failedDeletes", deleteKeys.toString());
    if (!result.getErrors().isEmpty()) {
      AUDIT.logWriteFailure(buildAuditMessageForFailure(s3GAction,
          auditMap, new Exception("MultiDelete Exception")));
    } else {
      AUDIT.logWriteSuccess(
          buildAuditMessageForSuccess(s3GAction, auditMap));
    }
    return result;
  }

  /**
   * Implement acl get.
   * <p>
   * see: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html
   */
  public S3BucketAcl getAcl(String bucketName)
      throws OS3Exception, IOException {
    long startNanos = Time.monotonicNowNanos();
    S3BucketAcl result = new S3BucketAcl();
    try {
      OzoneBucket bucket = getBucket(bucketName);
      S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
      S3Owner owner = S3Owner.of(bucket.getOwner());
      result.setOwner(owner);

      // TODO: remove this duplication avoid logic when ACCESS and DEFAULT scope
      // TODO: are merged.
      // Use set to remove ACLs with different scopes(ACCESS and DEFAULT)
      Set<Grant> grantSet = new HashSet<>();
      // Return ACL list
      for (OzoneAcl acl : bucket.getAcls()) {
        List<Grant> grants = S3Acl.ozoneNativeAclToS3Acl(acl);
        grantSet.addAll(grants);
      }
      ArrayList<Grant> grantList = new ArrayList<>();
      grantList.addAll(grantSet);
      result.setAclList(
          new S3BucketAcl.AccessControlList(grantList));
      return result;
    } catch (OMException ex) {
      getMetrics().updateGetAclFailureStats(startNanos);
      auditReadFailure(S3GAction.GET_ACL, ex);
      if (ex.getResult() == ResultCodes.BUCKET_NOT_FOUND) {
        throw newError(S3ErrorTable.NO_SUCH_BUCKET, bucketName, ex);
      } else if (isAccessDenied(ex)) {
        throw newError(S3ErrorTable.ACCESS_DENIED, bucketName, ex);
      } else {
        throw newError(S3ErrorTable.INTERNAL_ERROR, bucketName, ex);
      }
    } catch (OS3Exception ex) {
      getMetrics().updateGetAclFailureStats(startNanos);
      throw ex;
    }
  }

  /**
   * Implement acl put.
   * <p>
   * see: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
   */
  public Response putAcl(String bucketName,
                         InputStream body) throws IOException, OS3Exception {
    long startNanos = Time.monotonicNowNanos();
    String grantReads = headers.getHeaderString(S3Acl.GRANT_READ);
    String grantWrites = headers.getHeaderString(S3Acl.GRANT_WRITE);
    String grantReadACP = headers.getHeaderString(S3Acl.GRANT_READ_CAP);
    String grantWriteACP = headers.getHeaderString(S3Acl.GRANT_WRITE_CAP);
    String grantFull = headers.getHeaderString(S3Acl.GRANT_FULL_CONTROL);

    try {
      OzoneBucket bucket = getBucket(bucketName);
      S3Owner.verifyBucketOwnerCondition(headers, bucketName, bucket.getOwner());
      OzoneVolume volume = getVolume();

      List<OzoneAcl> ozoneAclListOnBucket = new ArrayList<>();
      List<OzoneAcl> ozoneAclListOnVolume = new ArrayList<>();

      if (grantReads == null && grantWrites == null && grantReadACP == null
          && grantWriteACP == null && grantFull == null) {
        S3BucketAcl putBucketAclRequest =
            new PutBucketAclRequestUnmarshaller().readFrom(body);
        // Handle grants in body
        ozoneAclListOnBucket.addAll(
            S3Acl.s3AclToOzoneNativeAclOnBucket(putBucketAclRequest));
        ozoneAclListOnVolume.addAll(
            S3Acl.s3AclToOzoneNativeAclOnVolume(putBucketAclRequest));
      } else {

        // Handle grants in headers
        if (grantReads != null) {
          ozoneAclListOnBucket.addAll(getAndConvertAclOnBucket(grantReads,
              S3Acl.ACLType.READ.getValue()));
          ozoneAclListOnVolume.addAll(getAndConvertAclOnVolume(grantReads,
              S3Acl.ACLType.READ.getValue()));
        }
        if (grantWrites != null) {
          ozoneAclListOnBucket.addAll(getAndConvertAclOnBucket(grantWrites,
              S3Acl.ACLType.WRITE.getValue()));
          ozoneAclListOnVolume.addAll(getAndConvertAclOnVolume(grantWrites,
              S3Acl.ACLType.WRITE.getValue()));
        }
        if (grantReadACP != null) {
          ozoneAclListOnBucket.addAll(getAndConvertAclOnBucket(grantReadACP,
              S3Acl.ACLType.READ_ACP.getValue()));
          ozoneAclListOnVolume.addAll(getAndConvertAclOnVolume(grantReadACP,
              S3Acl.ACLType.READ_ACP.getValue()));
        }
        if (grantWriteACP != null) {
          ozoneAclListOnBucket.addAll(getAndConvertAclOnBucket(grantWriteACP,
              S3Acl.ACLType.WRITE_ACP.getValue()));
          ozoneAclListOnVolume.addAll(getAndConvertAclOnVolume(grantWriteACP,
              S3Acl.ACLType.WRITE_ACP.getValue()));
        }
        if (grantFull != null) {
          ozoneAclListOnBucket.addAll(getAndConvertAclOnBucket(grantFull,
              S3Acl.ACLType.FULL_CONTROL.getValue()));
          ozoneAclListOnVolume.addAll(getAndConvertAclOnVolume(grantFull,
              S3Acl.ACLType.FULL_CONTROL.getValue()));
        }
      }
      // A put request will reset all previous ACLs on bucket
      bucket.setAcl(ozoneAclListOnBucket);
      // A put request will reset input user/group's permission on volume
      List<OzoneAcl> acls = bucket.getAcls();
      List<OzoneAcl> aclsToRemoveOnVolume = new ArrayList<>();
      List<OzoneAcl> currentAclsOnVolume = volume.getAcls();
      // Remove input user/group's permission from Volume first
      if (!currentAclsOnVolume.isEmpty()) {
        for (OzoneAcl acl : acls) {
          if (acl.getAclScope() == ACCESS) {
            aclsToRemoveOnVolume.addAll(OzoneAclUtil.filterAclList(
                acl.getName(), acl.getType(), currentAclsOnVolume));
          }
        }
        for (OzoneAcl acl : aclsToRemoveOnVolume) {
          volume.removeAcl(acl);
        }
      }
      // Add new permission on Volume
      for (OzoneAcl acl : ozoneAclListOnVolume) {
        volume.addAcl(acl);
      }
    } catch (OMException exception) {
      getMetrics().updatePutAclFailureStats(startNanos);
      auditWriteFailure(S3GAction.PUT_ACL, exception);
      if (exception.getResult() == ResultCodes.BUCKET_NOT_FOUND) {
        throw newError(S3ErrorTable.NO_SUCH_BUCKET, bucketName, exception);
      } else if (isAccessDenied(exception)) {
        throw newError(S3ErrorTable.ACCESS_DENIED, bucketName, exception);
      }
      throw exception;
    } catch (OS3Exception ex) {
      getMetrics().updatePutAclFailureStats(startNanos);
      throw ex;
    }
    getMetrics().updatePutAclSuccessStats(startNanos);
    return Response.status(HttpStatus.SC_OK).build();
  }

  /**
   * Example: x-amz-grant-write: \
   * uri="http://acs.amazonaws.com/groups/s3/LogDelivery", id="111122223333", \
   * id="555566667777".
   */
  private List<OzoneAcl> getAndConvertAclOnBucket(String value,
                                                  String permission)
      throws OS3Exception {
    List<OzoneAcl> ozoneAclList = new ArrayList<>();
    if (StringUtils.isEmpty(value)) {
      return ozoneAclList;
    }
    String[] subValues = value.split(",");
    for (String acl : subValues) {
      String[] part = acl.split("=");
      if (part.length != 2) {
        throw newError(S3ErrorTable.INVALID_ARGUMENT, acl);
      }
      S3Acl.ACLIdentityType type =
          S3Acl.ACLIdentityType.getTypeFromHeaderType(part[0]);
      if (type == null || !type.isSupported()) {
        LOG.warn("S3 grantee {} is null or not supported", part[0]);
        throw newError(NOT_IMPLEMENTED, part[0]);
      }
      // Build ACL on Bucket
      EnumSet<IAccessAuthorizer.ACLType> aclsOnBucket = S3Acl.getOzoneAclOnBucketFromS3Permission(permission);
      OzoneAcl defaultOzoneAcl = OzoneAcl.of(
          IAccessAuthorizer.ACLIdentityType.USER, part[1], OzoneAcl.AclScope.DEFAULT, aclsOnBucket
      );
      OzoneAcl accessOzoneAcl = OzoneAcl.of(IAccessAuthorizer.ACLIdentityType.USER, part[1], ACCESS, aclsOnBucket);
      ozoneAclList.add(defaultOzoneAcl);
      ozoneAclList.add(accessOzoneAcl);
    }
    return ozoneAclList;
  }

  private List<OzoneAcl> getAndConvertAclOnVolume(String value,
                                                  String permission)
      throws OS3Exception {
    List<OzoneAcl> ozoneAclList = new ArrayList<>();
    if (StringUtils.isEmpty(value)) {
      return ozoneAclList;
    }
    String[] subValues = value.split(",");
    for (String acl : subValues) {
      String[] part = acl.split("=");
      if (part.length != 2) {
        throw newError(S3ErrorTable.INVALID_ARGUMENT, acl);
      }
      S3Acl.ACLIdentityType type =
          S3Acl.ACLIdentityType.getTypeFromHeaderType(part[0]);
      if (type == null || !type.isSupported()) {
        LOG.warn("S3 grantee {} is null or not supported", part[0]);
        throw newError(NOT_IMPLEMENTED, part[0]);
      }
      // Build ACL on Volume
      EnumSet<IAccessAuthorizer.ACLType> aclsOnVolume =
          S3Acl.getOzoneAclOnVolumeFromS3Permission(permission);
      OzoneAcl accessOzoneAcl = OzoneAcl.of(IAccessAuthorizer.ACLIdentityType.USER, part[1], ACCESS, aclsOnVolume);
      ozoneAclList.add(accessOzoneAcl);
    }
    return ozoneAclList;
  }

  private void addKey(ListObjectResponse response, OzoneKey next) {
    KeyMetadata keyMetadata = new KeyMetadata();
    keyMetadata.setKey(EncodingTypeObject.createNullable(next.getName(),
        response.getEncodingType()));
    keyMetadata.setSize(next.getDataSize());
    String eTag = next.getMetadata().get(ETAG);
    if (eTag != null) {
      keyMetadata.setETag(ObjectEndpoint.wrapInQuotes(eTag));
    }
    keyMetadata.setStorageClass(S3StorageType.fromReplicationConfig(
        next.getReplicationConfig()).toString());
    keyMetadata.setLastModified(next.getModificationTime());
    String displayName = next.getOwner();
    keyMetadata.setOwner(S3Owner.of(displayName));
    response.addKey(keyMetadata);
  }

  @VisibleForTesting
  public void setOzoneConfiguration(OzoneConfiguration config) {
    this.ozoneConfiguration = config;
  }

  @VisibleForTesting
  public OzoneConfiguration getOzoneConfiguration() {
    return this.ozoneConfiguration;
  }

  @VisibleForTesting
  public void setHeaders(HttpHeaders headers) {
    this.headers = headers;
  }

  @Override
  @PostConstruct
  public void init() {
    listKeysShallowEnabled = ozoneConfiguration.getBoolean(
        OZONE_S3G_LIST_KEYS_SHALLOW_ENABLED,
        OZONE_S3G_LIST_KEYS_SHALLOW_ENABLED_DEFAULT);
    maxKeysLimit = ozoneConfiguration.getInt(
        OZONE_S3G_LIST_MAX_KEYS_LIMIT,
        OZONE_S3G_LIST_MAX_KEYS_LIMIT_DEFAULT);
  }
}
